# Browser integration

## Using the modified Chromium build

```yaml
browser:
  executable_path: /opt/our-chromium/chrome   # takes precedence over `channel`
  headless: true
```

Run `duc -c cfg.yaml browser-info` first. It launches the browser exactly as
verification does and prints the recorded identity; if the browser cannot be
launched or controlled it exits with status 3 and says why.

### Compatibility requirements and limitations

* The build must accept Playwright's Chromium launch flags and support the Chrome
  DevTools Protocol over `--remote-debugging-pipe`. Playwright supports Chromium
  versions close to the one it bundles; a build far older/newer may fail to launch
  or lose features (download events, per-context proxies). Pin the Playwright
  version that matches your branch.
* Download behaviour must not be altered by automation. The tool sets
  `acceptDownloads` (required to observe downloads) and launches with
  `BASE_ARGS` in `browser/environment.py` (QUIC/WebRTC-UDP off, background
  networking off) — none of which change render-vs-download decisions. Do not add
  flags that do.
* **Headless mode matters.** Playwright's default headless binary
  (`chrome-headless-shell`) has no PDF viewer, so PDFs that a normal browser renders
  are *downloaded*. The default here is `channel: chromium` (full Chromium, new
  headless), which renders PDFs inline like a desktop browser. The fixture suite
  checks this. The mode is recorded as `settings.headless_mode`
  (`headless_shell`, `new_headless`, `headed`).
* Other differences between automated and user browsing remain: no extensions,
  no user profile, no prior site engagement, default (not user-chosen) download
  settings, and Safe Browsing / download protection behaviour may differ from a
  managed install. Observations reflect the configured browser only.
* Enterprise policies or Safe Browsing in your build can block downloads; such
  outcomes are recorded faithfully as failures (the browser's failure string is
  kept verbatim).

## Recorded identity

Stored in `browser_configs` and `run_manifest.json`, referenced from every
observation via `browser_config_id` (a hash of the identity):

`executable_path`, `executable_sha256`, `browser_name`, `browser_version` (from
CDP), `playwright_version`, `python_version`, `os`, `machine`, `headless`,
`channel`, `launch_args`, and `settings` (`headless_mode`, `egress_proxy`,
`accept_downloads`, `chromium_sandbox`, `service_workers=block`,
`fresh_context_per_verification`, timeouts). The collection configuration is
fingerprinted separately (`config_fingerprint`).

## Verification semantics

* **Fresh context per verification**: no cookies, storage, cache or credentials;
  service workers blocked. Direct downloads are verified without borrowed state.
* **Listeners first**: download listeners are attached to the context's `page`
  event before any page exists, so downloads from popups and new tabs are captured.
* **Aborted navigations**: when a navigation turns into a download, Playwright
  raises "Download is starting" / `net::ERR_ABORTED`. This is treated as expected
  and the download event is awaited (`navigation_aborted_for_download=true`).
* **Completion**: the verifier waits for the download to finish
  (`download.failure()`), records failures verbatim, cancels on timeout, and only
  then hashes the saved file.
* **Interactions**: rendered pages are scanned for explicit download controls
  (`[download]`, scripted controls, buttons/links whose text says "download",
  `data-download*`). Each control is clicked in its own fresh context; steps are
  stored as structured replay (`goto`, `click` with CSS selector). An HTTP(S)
  download URL found this way is verified independently by direct navigation; if
  that fails and cookies/POST/non-GET were involved the observation is
  `session_dependent`. `blob:`/`data:` downloads are `generated_download` and never
  enter URL-only outputs.

## Feature-collector hook

The custom feature collector's private API is not modelled. Instead the verifier
calls a hook object you provide:

```python
# my_collector.py
class Hook:
    async def on_context_created(self, context, info): ...   # before any navigation
    async def on_download_started(self, download, info): ... # from the download event
    async def on_observation(self, observation, info):       # after classification
        return "feature-record-id"                           # stored as feature_ref
    async def close(self): ...

def factory(config):
    return Hook()
```

```yaml
browser:
  feature_collector: "my_collector:factory"
```

`context`, `download` are public Playwright objects (you can open a CDP session
with `await context.new_cdp_session(page)`); `info` carries `run_id`,
`candidate_id`, `mode`, `initiating_url`, `source_page` and `browser_config_id`.
The returned reference links detector features to the observation without mixing
them into labeling evidence. `tests/hook_impl.py` is a working example.
