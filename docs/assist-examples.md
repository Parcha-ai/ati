# ATI Assist — Sample Responses

Real output from `ati assist`. These are actual LLM responses showing how assist answers agent questions with actionable commands, not dry tool lists.

---

## Multi-Step Workflow: Lip-Sync Video (unscoped)

```
$ ati assist "trying to make a lip sync video of tech streamer praising ati.tools"
```

> Great project! Here's the workflow to create a lip-synced tech streamer video praising ati.tools:
>
> ## Step 1: Generate the tech streamer face
> ```bash
> ati run fal__submit --endpoint_id "fal-ai/flux-2-turbo" \
>   --prompt "Professional tech streamer, young male with glasses, front-facing portrait, good lighting, neutral expression, 4K quality" \
>   --image_size "portrait_4_3" \
>   --num_images 1
> ```
> Save the `request_id` and get the image URL with `fal__result`.
>
> ## Step 2: Generate the audio (praise script)
> ```bash
> ati run fal__submit --endpoint_id "fal-ai/elevenlabs/tts/eleven-v3" \
>   --text "Hey everyone, I've been using ati.tools and it's absolutely incredible! The CLI tool integration is seamless, and the AI agent capabilities are next-level. If you're serious about AI automation, you need to check this out!" \
>   --voice_id "cjVigY5qzO86Huf0OWal" \
>   --model_id "eleven_multilingual_v2"
> ```
> Save the `request_id` and get the audio URL with `fal__result`.
>
> ## Step 3: Lip-sync the video
> ```bash
> ati run fal__submit --endpoint_id "fal-ai/veed/fabric/1.0" \
>   --image_url "YOUR_IMAGE_URL_FROM_STEP_1" \
>   --audio_url "YOUR_AUDIO_URL_FROM_STEP_2"
> ```
> Check status with `fal__status`, then get the final video URL with `fal__result`.
>
> **Tips:**
> - Use `voice_id "cjVigY5qzO86Huf0OWal"` for an energetic, friendly male voice (Mike/Eric)
> - Keep the script under 60 seconds for best lip-sync quality
> - The face image should be front-facing with good lighting and neutral expression

---

## Scoped Query: Lip-Sync (scoped to fal provider)

```
$ ati assist fal "I want to create a lip-synced talking head video"
```

> To create a lip-synced talking head video, you'll use **VEED Fabric 1.0** on fal.ai. You need:
> - A face image URL (headshot/portrait)
> - An audio URL (speech)
>
> ### 1. Submit the Lip-Sync Job
>
> ```bash
> ati run fal__submit \
>   --endpoint_id "veed/fabric-1.0" \
>   --image_url "https://example.com/face.jpg" \
>   --audio_url "https://example.com/speech.mp3"
> ```
>
> This returns a `request_id` for polling.
>
> ### 2. Check Status
>
> ```bash
> ati run fal__status \
>   --endpoint_id "veed/fabric-1.0" \
>   --request_id "YOUR_REQUEST_ID"
> ```
>
> Returns: `IN_QUEUE`, `IN_PROGRESS`, or `COMPLETED`
>
> ### 3. Get Result (when COMPLETED)
>
> ```bash
> ati run fal__result \
>   --endpoint_id "veed/fabric-1.0" \
>   --request_id "YOUR_REQUEST_ID"
> ```
>
> Returns the generated video URL.
>
> **Best Practices:**
> - Face image: front-facing, good lighting, neutral expression
> - Audio: clean speech, no background noise
> - Keep under 60 seconds per segment for best results

---

## Tool Discovery: Stock Prices

```
$ ati assist "do we have a tool to search for stock prices?"
```

> Yes, we have several stock price tools available:
>
> **For current/latest prices:**
> - `financial_datasets__getStockPriceSnapshot` — Get the latest price snapshot for a ticker
> - `finnhub__quote` — Real-time quote data for US stocks
>
> **For historical prices:**
> - `financial_datasets__getStockPrices` — Historical OHLCV data with customizable intervals (daily, weekly, etc.) and date ranges
>
> **Quick examples:**
>
> ```bash
> # Latest price
> ati run financial_datasets__getStockPriceSnapshot --ticker AAPL
>
> # Real-time quote
> ati run finnhub__quote --symbol AAPL
>
> # Historical prices (last 30 days)
> ati run financial_datasets__getStockPrices --ticker AAPL --start_date 2024-12-01 --end_date 2024-12-31 --interval day
> ```
>
> **Gotchas:**
> - Use `financial_datasets__getStockPrices` if you need historical data or want to analyze trends over time
> - `finnhub__quote` is good for real-time quotes with more detail (includes open, high, low, volume, etc.)
> - All tools require the ticker symbol (e.g., AAPL, MSFT, GOOGL)

---

## CLI Scoped: GitHub Pull Request

```
$ ati assist gh "how do I create a pull request?"
```

> Use the `pr create` subcommand.
>
> **Basic command:**
> ```bash
> ati run gh -- pr create --title "Add new feature" --body "Description of changes" --base main
> ```
>
> **Key Flags:**
> - `--title`: The PR title.
> - `--body`: The PR description.
> - `--base`: The target branch (defaults to the repository's default branch).
> - `--head`: The source branch (defaults to the current branch).
> - `--draft`: Create the PR as a draft.
> - `--assignee`: Assign users (`@me` for yourself).
> - `--reviewer`: Request reviews from specific users or teams.
>
> **Example with options:**
> ```bash
> ati run gh -- pr create --title "Fix login bug" --base develop --draft --assignee @me
> ```
>
> **Gotcha:** You must have committed your changes and pushed the branch to GitHub before running this command.

---

## Compliance: Sanctions Screening

```
$ ati assist "screen a person named John Smith for sanctions"
```

> Use the `ca_person_sanctions_search` tool to screen John Smith against global sanctions lists (OFAC, UN, EU, and 40+ other national lists).
>
> ```bash
> ati run ca_person_sanctions_search --search_term "John Smith"
> ```
>
> This will return any potential matches with a `match_status` (no_match, potential_match, true_positive, false_positive) and `risk_level` (low, medium, high). If you need a shareable URL for compliance documentation, add `--share_url 1`.
>
> For a more comprehensive KYC check, you could also run `ca_person_pep_search` and `ca_person_adverse_media_search` to check for politically exposed person status and negative news coverage.

---

## Local LLM Support (`--local`)

`ati assist` supports a local LLM fallback via any OpenAI-compatible server (ollama, llama.cpp, llamafile). This is useful in air-gapped or sandboxed environments where cloud API keys aren't available.

```bash
# Explicit local mode
ati assist --local "what tools search the web?"

# Or via environment variable
ATI_ASSIST_PROVIDER=local ati assist "how to use github tools?"

# Auto-fallback: if no cloud keys are set, ati tries local automatically
```

**Environment variables:**

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_HOST` | `http://localhost:11434` | Local LLM server URL |
| `ATI_OLLAMA_MODEL` | `smollm3:3b` | Model name to use |
| `ATI_ASSIST_PROVIDER` | (auto-detect) | Force `local`, `cerebras`, or `anthropic` |

**Important caveats:** Local LLMs are currently best suited for GPU-equipped machines or future hardware. On CPU-only servers, inference is slow (1-2+ minutes for a single response) and smaller models (3B parameters) tend to ignore the rich tool context that makes `ati assist` useful. For production use, cloud providers (Cerebras, Anthropic) are strongly recommended. The local option exists as a zero-cost fallback and will improve as local models and hardware get better.

---

## Notes

- All examples are real LLM output from `ati assist` with the conversational prompts (March 2026)
- The LLM backend is Cerebras (zai-glm-4.7) with temperature 0.3 — responses vary slightly between runs but consistently include actionable `ati run` commands
- Scoped queries (`ati assist <provider> "question"`) give deeper answers about that provider's tools
- Unscoped queries search across all installed tools and pick the best matches
- Each response also includes a **Quick Reference** section (omitted here for brevity) with exact parameter schemas from the tool definitions
