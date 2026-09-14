"""attackmapper/llm_client.py — single shared entry point for every real
model call in AttackMapper.

Previously each of the five LLM-backed layers (discovery/evidence_llm.py,
inference/relationship_llm.py, narration/risk_llm.py,
narration/nl_interface.py, discovery/agentic_loop.py) carried its own
copy-pasted client setup calling Anthropic's native Messages API directly.
This module replaces all five copies with one implementation, talking to
models through OpenRouter (https://openrouter.ai) instead.

Why OpenRouter needs its own module rather than a drop-in key swap:
OpenRouter exposes an OpenAI-compatible `/chat/completions` endpoint, not
Anthropic's `/v1/messages` shape, so the call itself (client class, method
name, request/response shape) changes, not just the API key. See
https://openrouter.ai/docs/quickstart.

Model choice: DEFAULT_MODEL is `openrouter/free`, OpenRouter's "Free Models
Router" (https://openrouter.ai/docs/guides/routing/routers/free-router).
It auto-selects a working zero-cost model per request from OpenRouter's
pool of `:free`-variant models, filtering for whatever features the
request needs (e.g. tool calling). That's deliberately preferred here over
hardcoding one specific free model like `meta-llama/llama-3.3-70b-
instruct:free`: individual free models on OpenRouter come and go, get
deprecated, or hit their (fairly low) shared rate limits, while the router
itself stays a stable target. Any caller can still override `model=` per
call (or export ATTACKMAPPER_LLM_MODEL) to pin a specific model -- free
(any slug with a `:free` suffix, e.g. "deepseek/deepseek-chat-v3.1:free")
or paid -- without touching this file.

Per the master spec's testability rules, this module owns *only* the
network call. Schema validation, storage, and every other decision stay in
each layer's own module, and each layer keeps its own thin call_llm()
wrapper (now just delegating to send_prompt() below) so existing unit
tests that monkeypatch e.g. `evidence_llm.call_llm` keep working unchanged
-- nothing here needs those five modules to import this one at call time,
only at import time.
"""

from __future__ import annotations

import os

# OpenRouter's free-model router: picks a working zero-cost model per
# request instead of pinning to one specific `:free` model. See the
# module docstring above for why. Override with ATTACKMAPPER_LLM_MODEL or
# a per-call model= argument to pin a specific model instead.
DEFAULT_MODEL = os.environ.get("ATTACKMAPPER_LLM_MODEL", "openrouter/free")

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


def send_prompt(prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 1500) -> str:
    """Send one prompt to a model via OpenRouter and return its text reply.

    Reads OPENROUTER_API_KEY from the environment and raises a clear
    RuntimeError if the SDK isn't installed, the key isn't set, or the
    call fails -- callers shouldn't have to guess why an LLM call didn't
    run. The 'openai' package (used here purely as an OpenAI-compatible
    HTTP client, per OpenRouter's own recommended integration --
    https://openrouter.ai/docs/community/openai-sdk) is imported lazily so
    phases/tests that never call an LLM don't need it installed at all.

    Every prompt built by this project's prompts/ modules asks for a JSON
    object back (see ATTACKMAPPER_MASTER.md section 7), so two extra
    request options are always sent to make that reliable, especially
    against the free-model pool where individual models vary a lot in
    how well they follow "respond only with JSON" instructions:

    - `response_format={"type": "json_object"}` turns on OpenRouter's
      JSON mode (https://openrouter.ai/docs/api_reference/overview
      -> Structured Outputs). When `model` is the free router
      (`openrouter/free`), this also narrows the pool to free models
      that actually support structured output, per the router's own
      "filters for models that support features needed for your
      request" behavior -- this is the main fix for the "response was
      not valid JSON: Expecting value: line 1 column 1" failure mode,
      which usually means a model that ignored the JSON instruction
      entirely (or returned its answer in a separate `reasoning` field
      the code below never reads) got picked.
    - `reasoning={"effort": "none"}` asks reasoning-capable models to
      skip their hidden "thinking" tokens. Those tokens count against
      `max_tokens` just like real output, so on a reasoning model they
      can eat the whole budget before the actual JSON answer is
      written -- the likely cause of the "Unterminated string" /
      truncated-JSON failure mode. Non-reasoning models simply ignore
      this field.

    Both are best-effort: if a provider rejects an option it doesn't
    recognize, `send_prompt` retries once without it rather than
    failing the whole call outright.

    Two more environment variables are read, both optional and both
    purely cosmetic (they only affect OpenRouter's public leaderboards,
    never routing or billing):
    - OPENROUTER_SITE_URL -> sent as the HTTP-Referer header
    - OPENROUTER_SITE_NAME -> sent as the X-Title header
    See https://openrouter.ai/docs/app-attribution.

    OPENROUTER_BASE_URL can override the endpoint (e.g. to point at a
    proxy or a compatible self-hosted router); it defaults to
    OpenRouter's own API.
    """
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError(
            "the 'openai' package is required to call an LLM via OpenRouter "
            "(pip install openai)"
        ) from exc

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not set; AttackMapper's LLM-backed "
            "layers need it to call a model via OpenRouter"
        )

    base_url = os.environ.get("OPENROUTER_BASE_URL", DEFAULT_BASE_URL)
    client = OpenAI(base_url=base_url, api_key=api_key)

    extra_headers: dict[str, str] = {}
    site_url = os.environ.get("OPENROUTER_SITE_URL")
    site_name = os.environ.get("OPENROUTER_SITE_NAME")
    if site_url:
        extra_headers["HTTP-Referer"] = site_url
    if site_name:
        extra_headers["X-Title"] = site_name

    def _create(*, with_extras: bool):
        kwargs: dict = dict(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            extra_headers=extra_headers or None,
        )
        if with_extras:
            kwargs["response_format"] = {"type": "json_object"}
            kwargs["extra_body"] = {"reasoning": {"effort": "none"}}
        return client.chat.completions.create(**kwargs)

    try:
        response = _create(with_extras=True)
    except Exception:
        # Some providers 400 on response_format/reasoning fields they
        # don't recognize instead of ignoring them. Retry once without
        # either rather than failing the whole call over an optional
        # reliability improvement.
        try:
            response = _create(with_extras=False)
        except Exception as exc:  # openai's own exception hierarchy
            raise RuntimeError(f"LLM call failed: {exc}") from exc

    if not response.choices:
        return ""

    message = response.choices[0].message
    content = getattr(message, "content", None)
    if content:
        return content

    # A handful of reasoning models still return an empty `content`
    # alongside their reasoning even with reasoning.effort="none" (the
    # field is a hint, not a hard guarantee across every provider).
    # Falling back to the reasoning text is better than surfacing an
    # empty string as if the model had nothing to say -- the caller's
    # JSON-schema validation will reject it anyway if it isn't usable.
    reasoning = getattr(message, "reasoning", None)
    return reasoning or ""
