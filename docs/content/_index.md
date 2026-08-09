---
title: OpenRun
layout: hextra-home
description: "OpenRun is an open-source self-hosted PaaS alternative for teams deploying internal tools and web apps declaratively on a VPS or Kubernetes with GitOps, RBAC and SSO."
keywords:
  [
    "internal tools",
    "Streamlit apps",
    "FastAPI apps",
    "Gradio apps",
    "FastHTML apps",
    "NiceGUI apps",
    "operational scripts",
    "deployment platform",
    "GitOps",
    "self-hosted",
    "AI generated apps",
  ]
cascade:
  images: ["/openrun_small.png"]
---

<style>
.word-wheel { display: inline-block; position: relative; width: 6.4em; height: 2.6em; perspective: 600px; transition: width 0.6s cubic-bezier(0.22, 0.61, 0.36, 1); -webkit-mask-image: linear-gradient(to bottom, transparent, #000 16%, #000 84%, transparent); mask-image: linear-gradient(to bottom, transparent, #000 16%, #000 84%, transparent); }
.word-wheel::before { content: "\200B"; line-height: 2.6em; }
.ww-word { position: absolute; top: 50%; left: 50%; white-space: nowrap; transition: transform 0.6s cubic-bezier(0.22, 0.61, 0.36, 1), opacity 0.6s ease; background: linear-gradient(180deg, #00C200, #007700); -webkit-background-clip: text; background-clip: text; color: transparent; }
.ww-c { transform: translate(-50%, -50%); opacity: 1; }
.ww-m1 { transform: translate(-50%, -50%) translateY(-0.95em) rotateX(38deg) scale(0.62); opacity: 0.5; }
.ww-p1 { transform: translate(-50%, -50%) translateY(0.95em) rotateX(-38deg) scale(0.62); opacity: 0.5; }
.ww-m2 { transform: translate(-50%, -50%) translateY(-1.5em) rotateX(60deg) scale(0.45); opacity: 0; }
.ww-p2 { transform: translate(-50%, -50%) translateY(1.5em) rotateX(-60deg) scale(0.45); opacity: 0; }
.ww-sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; }
@media (prefers-reduced-motion: reduce) { .ww-word { transition: none; } .ww-word:not(.ww-c) { visibility: hidden; } }
@media (max-width: 767px) { #hero-headline { text-align: center; } .word-wheel { display: block; width: auto !important; margin: 0 auto; } }
</style>

<div class="hx:mb-4">
<h1 id="hero-headline" class="not-prose hx:text-4xl hx:font-bold hx:leading-none hx:tracking-tighter hx:md:text-5xl hx:py-2"><span class="hx:bg-clip-text hx:text-transparent hx:bg-gradient-to-r hx:from-gray-900 hx:to-gray-600 hx:dark:from-gray-100 hx:dark:to-gray-400">Self-hosted platform for</span><span class="ww-sr">&nbsp;internal tools</span> <span id="word-wheel" class="word-wheel" aria-hidden="true"><span class="ww-word ww-m2">Hypermedia apps</span><span class="ww-word ww-m1">automation scripts</span><span class="ww-word ww-c">internal tools</span><span class="ww-word ww-p1">AI apps</span><span class="ww-word ww-p2">Streamlit apps</span></span></h1>
</div>

<div class="hx:mb-6">
{{< hextra/hero-subtitle >}}
  Deploy internal tools and team web apps on infrastructure you control.&nbsp;<br class="hx:sm:block hx:hidden"/>Run on a VPS or Kubernetes with GitOps, RBAC, SSO, and audit logs built in.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx:mb-2 hx:flex hx:flex-wrap hx:gap-1">
{{< hextra/hero-button style="border-radius: 8px;" text="QuickStart" link="docs/quickstart" >}}
{{< hextra/hero-button style="border-radius: 8px;" text="Teams" link="docs/use-cases/team" >}}
{{< hextra/hero-button style="border-radius: 8px;" text="Demo" link="https://utils.demo.clace.io/console" >}}
</div>

<div class="hx:mt-8 hx:mb-8 hx:max-w-4xl">
<h2 class="hx:text-2xl hx:font-bold hx:tracking-tight">Self-Hosted PaaS Alternative for Internal Tools</h2>
<p class="hx:mt-2 hx:text-gray-600 hx:dark:text-gray-400">OpenRun is built for teams that deploy and operate internal tools, dashboards, automation interfaces and business web apps. It provides a Platform-as-a-Service (PaaS) style workflow while keeping application code, data and infrastructure under your organization's control.</p>
<p class="hx:mt-2 hx:text-gray-600 hx:dark:text-gray-400">Start on a Linux VPS or private server with Docker or Podman, then move the same declarative applications to Kubernetes when your team needs a distributed deployment. GitOps, SSO, RBAC, audit logs, service bindings, automatic TLS and scale-to-zero are built in.</p>
</div>

{{< hextra/feature-grid >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="What is OpenRun?" icon="information-circle" subtitle="<br>OpenRun is an open-source, self-hosted PaaS alternative for teams deploying internal tools and web apps. Run it on a VPS or private server with Docker/Podman, or on a Kubernetes cluster.<br><br>OpenRun adds the authentication, authorization and auditing features required for team use. Code-first apps get the platform capabilities usually found in enterprise low-code tools like Retool." class="openrun-feature-card openrun-feature-card-dark" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="Motivation" icon="flag" subtitle="<br>OpenRun is built with these goals:<br><br>➣ Declarative deployments made simple<br>➣ Start on single-node, scale to Kubernetes if needed<br>➣ Make auth and RBAC easy for internal tools<br>➣ Easy SAML support without paying the SSO tax<br>➣ Run thousands of apps - zero idle resource usage" class="openrun-feature-card openrun-feature-card-dark" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="OpenRun Features" icon="light-bulb" subtitle="<br>Some of the unique features of OpenRun are:<br>➣ Create and manage apps declaratively<br>➣ Easily upgrade from single-node to K8S <br>➣ Domain based or path based routing, with auto-TLS<br>➣ OAuth/OpenID/SAML/Cert auth, with RBAC<br>➣ Scales idle apps down to zero<br>➣ Staged deployment, for code and config changes<br>➣ Atomic (all or nothing) updates across apps<br>➣ Managed SQLite + Litestream replication to S3" class="openrun-feature-card openrun-feature-card-dark" >}}

{{< /hextra/feature-grid >}}

<div style="height: 20px;"></div>

<div style="position: relative; width: 100vw; margin-left: calc(-50vw + 50%); background: #007700; color: white; justify-content: center; box-sizing: border-box; padding: 25px; font-family: 'Inter', 'Segoe UI', 'Helvetica Neue', 'Roboto', 'Arial', sans-serif;">
<div style="max-width: 800px; width: 100%; margin: 0 auto; padding: 1rem;">

<div style="font-weight: bold; margin-bottom: 20px; text-align: center;font-size: 28px; color: #FEF08A; font-weight: 800; text-shadow: 0 2px 3px rgba(0,0,0,0.75), 0 0 14px rgba(254,240,138,0.35);">Installation</div>
<div style="position: relative;">
<div style="font-weight: bold; margin-bottom: 10px; color: #ECFCCB; font-weight: 700;">Install OpenRun:</div>
<div style="padding-inline: 10px; padding-top: 5px; padding-bottom: 20px; font-size: 14px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;" id="code1">
curl -sSL https://openrun.dev/install.sh | sh
</div>
<button title="Copy" style="position: absolute; top: 5px; right: 5px; padding: 10px 10px 1px 10px; font-size: 14px; cursor: pointer;" onclick="copyCode('code1', this)">⧉</button>
</div>

<div style="position: relative;">
<div style="font-weight: bold; margin-bottom: 10px; color: #ECFCCB; font-weight: 700;">Start OpenRun server (in a new window):</div>
<div style="padding-inline: 10px; padding-top: 5px; padding-bottom: 20px; font-size: 14px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;" id="code2">
openrun server start &
</div>
<button title="Copy" style="position: absolute; top: 5px; right: 5px;  padding: 10px 10px 1px 10px; font-size: 14px; cursor: pointer;" onclick="copyCode('code2', this)">⧉</button>
</div>

<div style="font-weight: bold; margin-bottom: 20px; text-align: center;font-size: 28px; color: #FEF08A; font-weight: 800; text-shadow: 0 2px 3px rgba(0,0,0,0.75), 0 0 14px rgba(254,240,138,0.35);">GitOps in One Command</div>

<div style="position: relative;">
<div style="font-weight: bold; margin-bottom: 10px; color: #ECFCCB; font-weight: 700;">Schedule a sync:</div>
<div style="padding-inline: 10px; padding-top: 5px; padding-bottom: 20px; font-size: 14px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;" id="code3">
openrun sync schedule --approve --promote \ &nbsp;&nbsp;github.com/openrundev/openrun/examples/utils.star
</div>
<button title="Copy" style="position: absolute; top: 5px; right: 5px; padding: 10px 10px 1px 10px; font-size: 14px; cursor: pointer;" onclick="copyCode('code3', this)">⧉</button>
</div>

<div style="margin-top: 5px; margin-bottom: 5px; text-align: center;font-size: 16px; color: lightgray;">Starts a background sync which automatically creates new apps and updates existing apps, reading latest app config and code from Git.</div>

</div>
</div>

<style>
  .sample-config-box { width: 92%; }
  @media screen and (min-width: 768px) { .sample-config-box { width: 50%; } }
</style>
<div style="position: relative; width: 100vw; margin-left: calc(-50vw + 50%); display: flex; flex-direction: column; align-items: center; padding: 40px 0; box-sizing: border-box;">
<div style="font-weight: bold; margin-bottom: 20px; text-align: center;font-size: 28px; color: #00C200; font-weight: 800;">Sample OpenRun Config</div>
<div class="sample-config-box" style="border-radius: 10px; overflow: hidden; border: 1px solid rgba(127,127,127,0.25); box-shadow: 0 2px 12px rgba(0,0,0,0.08);">
<div style="padding: 10px 16px; font-size: 13px; font-weight: 600; letter-spacing: 0.02em; background: rgba(127,127,127,0.10); border-bottom: 1px solid rgba(127,127,127,0.2);">sample.star</div>
<pre style="margin: 0; padding: 2px 20px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace; font-size: 13.5px; line-height: 1.6; overflow-x: auto; background: rgba(127,127,127,0.04);"><code style="font-family: inherit;">
<span style="color: #6a737d; font-style: italic;"># Set resource limits (optional)</span>
limits = {<span style="color: #22863a;">&quot;cpus&quot;</span>: <span style="color: #22863a;">&quot;1&quot;</span>, <span style="color: #22863a;">&quot;memory&quot;</span>: <span style="color: #22863a;">&quot;512m&quot;</span>}
<span></span>

<span style="color: #6a737d; font-style: italic;"># Streamlit App Declaration</span>
app(path=<span style="color: #22863a;">&quot;/misc/streamlit_example&quot;</span>, source=<span style="color: #22863a;">&quot;github.com/streamlit/streamlit-example&quot;</span>,
&nbsp;&nbsp;&nbsp;&nbsp;git_branch=<span style="color: #22863a;">&quot;master&quot;</span>, spec=<span style="color: #22863a;">&quot;python-streamlit&quot;</span>, container_opts=limits)

<span style="color: #6a737d; font-style: italic;"># FastHTML App Declaration</span>
app(path=<span style="color: #22863a;">&quot;fasthtml.:&quot;</span>, source=<span style="color: #22863a;">&quot;github.com/AnswerDotAI/fasthtml/examples&quot;</span>,
&nbsp;&nbsp;&nbsp;&nbsp;spec=<span style="color: #22863a;">&quot;python-fasthtml&quot;</span>, params={<span style="color: #22863a;">&quot;APP_MODULE&quot;</span>:<span style="color: #22863a;">&quot;basic_ws:app&quot;</span>}, container_opts=limits)

<span style="color: #6a737d; font-style: italic;"># This is the complete build and deployment config for two apps.</span>
</code></pre>

</div>
</div>

<script>
(function () {
    const wheel = document.getElementById('word-wheel');
    if (!wheel) return;
    const words = ['internal tools', 'AI apps', 'Streamlit apps', 'FastAPI apps', 'Gradio apps', 'FastHTML apps', 'NiceGUI apps', 'Hypermedia apps', 'operational tools', 'runbook automation'];
    const posCls = ['ww-m2', 'ww-m1', 'ww-c', 'ww-p1', 'ww-p2'];
    const spans = Array.from(wheel.children);
    const measure = document.createElement('span');
    measure.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;';
    wheel.appendChild(measure);
    let cur = 0;
    const setWidth = () => { measure.textContent = words[cur]; wheel.style.width = measure.offsetWidth + 'px'; };
    spans.forEach((s, i) => { s.textContent = words[(i - 2 + words.length) % words.length]; });
    setWidth();
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(setWidth);
    window.addEventListener('resize', setWidth);
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    setInterval(() => {
        if (document.hidden) return;
        cur = (cur + 1) % words.length;
        const top = spans.shift();
        top.textContent = words[(cur + 2) % words.length];
        spans.push(top);
        spans.forEach((s, i) => { s.className = 'ww-word ' + posCls[i]; });
        setWidth();
    }, 2600);
})();

function copyCode(codeId, buttonElem) {
    const code = document.getElementById(codeId).textContent;
    navigator.clipboard.writeText(code).then(() => {
        const originalText = buttonElem.textContent;
        buttonElem.textContent = 'Copied!';
        setTimeout(() => {
            buttonElem.textContent = originalText;
        }, 2000);
    }).catch(err => {
        console.error('Copy failed', err);
    });
}
</script>

<!--div style="height: 20px;"></div>

<div  style="position:relative; width:100%; max-width:560px; padding-bottom:5%; margin:0 auto; overflow:hidden;">
<iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/YrWNz4JQ6p0?si=tnjma2uqBp2OrE7m" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
</div-->

<div style="height: 20px;"></div>

{{< hextra/feature-grid >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Container management" link="docs/quickstart/#containerized-applications" subtitle="Build and deploy containerized web applications declaratively across Docker, Podman or Kubernetes using one consistent platform configuration."  icon="docker" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Declarative GitOps" link="docs/quickstart/#lifecycle-with-git" subtitle="Manage staged deployments, versioned releases and preview environments through declarative GitOps workflows connected to GitHub or GitLab."  icon="github" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Scale down to zero" link="/docs/container/overview/" subtitle="Initialize applications lazily on their first request, then automatically pause idle containers and reduce resource usage to zero."  icon="pause" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="PostgreSQL + MySQL Service Bindings" link="/docs/applications/servicebindings" subtitle="Automatically provision isolated PostgreSQL schemas and roles or MySQL databases and users, then inject unique application credentials securely."  icon="database" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="SQLite + Litestream" link="/docs/applications/litestream/" subtitle="Run stateful SQLite applications with persistent volumes, continuous Litestream replication to S3-compatible storage and automatic disaster recovery." icon="cloud-upload" class="openrun-feature-card openrun-feature-card-light" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Flexible Auth" link="/docs/configuration/authentication/" subtitle="Protect every application with OAuth, OpenID Connect, SAML or client-certificate authentication plus flexible role-based access controls."  icon="shield-check" class="openrun-feature-card openrun-feature-card-light" >}}

{{< /hextra/feature-grid >}}

<div style="height: 20px;"></div>

{{< hextra/feature-grid >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Comparison with self-hosted PaaS platforms" icon="scale" subtitle="Compared with self-hosted PaaS platforms like Coolify, Kamal and Dokku, OpenRun provides:<br />➣ A **declarative GitOps** interface for application code and configuration<br/>➣ Scale-to-zero for idle web apps<br/>➣ Single-binary deployment to a VPS with Docker/Podman, or to Kubernetes<br/>➣ Built-in OAuth/OIDC/SAML, RBAC and audit logs. Auth is done for apps also, not just the OpenRun console<br/><br/>OpenRun is a self-hosted PaaS alternative focused on web apps and internal tools. It does not deploy arbitrary databases or Docker Compose stacks like a full general-purpose PaaS. OpenRun instead supports service bindings which allows your apps to get easy access to a externally managed database/service." class="openrun-feature-card openrun-feature-card-dark" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Comparison with DIY on Kubernetes" icon="cog" subtitle="Running OpenRun on Kubernetes gives you the benefits of Kubernetes without the pain. OpenRun provides:<br/>➣ Unified interface as against glueing together services like Jenkins for builds, ArgoCD/FluxCD for CD, IDP for app management etc.<br/>➣ Simple declarative config, **no YAML files, no webserver DSLs**.<br/>➣ Support for setting up auth policies using RBAC.<br/><br/>Compared to **Knative**, OpenRun has a much simpler config without requiring YAML files. Resource usage is lower with OpenRun since apps are loaded lazily, on the first API call. OpenRun app versions are maintained in the metadata database, reducing Kubernetes resources created. Knative requires an external build system and does not support auth for apps." class="openrun-feature-card openrun-feature-card-dark" >}}

{{< hextra/feature-card title="Common use cases" icon="users" subtitle="OpenRun can be used by teams to:<br/>➣ For operations teams to provide an easy on-ramp to Kubernetes for dev teams<br/>➣  Deploy web apps with zero config required for most common frameworks like **Streamlit/Gradio/FastHTML/NiceGUI** etc.<br />➣ Replace Jenkins/Rundeck jobs, using OpenRun Actions for **automating operational scripts**<br/>➣ Expose web apps for internal REST APIs, replacing manual curl commands<br><br>While the auth and auditing features of OpenRun are built for use by teams, OpenRun can also be used by individuals for:<br/>➣ Zero-config dev env setup locally<br/>➣ Host web apps shared with friends and family, using OAuth" class="openrun-feature-card openrun-feature-card-dark" >}}

{{< /hextra/feature-grid >}}

<div style="height: 20px;"></div>

<style>
  @media screen and (min-width: 768px) {
    .responsive-picture { width: 60%; }
  }
  .mc-signup { max-width: 720px; margin: 0 auto; padding: 20px 28px; border-radius: 12px; background: radial-gradient(ellipse at 50% 80%, rgba(0,194,0,0.12), hsla(0,0%,100%,0)); border: 1px solid rgba(0,194,0,0.2); display: flex; align-items: center; justify-content: space-between; gap: 24px; flex-wrap: wrap; }
  .mc-signup-text { flex: 0 1 auto; min-width: 200px; }
  .mc-signup-form { flex: 1 1 320px; display: flex; align-items: center; gap: 10px; }
  .mc-signup-form input[type="email"] { flex: 1 1 180px; padding: 10px 14px; border: 1px solid rgba(0,194,0,0.35); border-radius: 8px; font-size: 14px; outline: none; background: transparent; color: inherit; }
  .mc-signup-form button { padding: 10px 24px; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; background: linear-gradient(135deg,#00C200,#2ED82E); color: white; white-space: nowrap; transition: opacity 0.2s; }
  .mc-signup-form button:hover { opacity: 0.85; }
  @media screen and (max-width: 600px) {
    .mc-signup { flex-direction: row; flex-wrap: wrap; justify-content: center; text-align: center; padding: 8px 10px; gap: 4px; width: 100%; max-width: none; align-self: stretch; box-sizing: border-box; }
    .mc-signup-text { flex: 1 1 100%; min-width: 0; }
    .mc-signup-text div { line-height: 1.3; }
    .mc-signup-form { flex: 1 1 100%; gap: 6px; margin-top: 4px; }
    .mc-signup-form input[type="email"] { flex: 1 1 auto; padding: 6px 10px; font-size: 13px; }
    .mc-signup-form button { padding: 6px 14px; font-size: 13px; }
  }
</style>

<video controls muted class="responsive-picture" style="display: block; margin-left: auto; margin-right: auto;">
  <source media="(prefers-color-scheme: dark)" src="https://openrun.dev/demo_dark.mp4" type="video/mp4">
  <source media="(prefers-color-scheme: light)" src="https://openrun.dev/demo_light.mp4" type="video/mp4">
</video>
<br>

<!-- Begin Mailchimp Signup Form --><div id="mc_embed_signup" class="mc-signup"><div class="mc-signup-text"><div style="font-size: 18px; font-weight: 700; margin-bottom: 4px; background: linear-gradient(135deg, #00C200, #2ED82E); color: transparent; background-clip: text; -webkit-background-clip: text;">Stay in the loop</div><div style="font-size: 13px; color: #6b7280;">Get updates on new features and releases.</div></div><form action="https://clace.us21.list-manage.com/subscribe/post?u=3e38430549570438cbc8b7513&amp;id=57d9eeea29&amp;f_id=00afa8e1f0" method="post" id="mc-embedded-subscribe-form" name="mc-embedded-subscribe-form" class="validate mc-signup-form" target="_blank"><input type="email" placeholder="Enter your email" name="EMAIL" id="mce-EMAIL" required><div aria-hidden="true" id="mce-responses" class="clear foot" style="display:none"><div class="response" id="mce-error-response" style="display:none"></div><div class="response" id="mce-success-response" style="display:none"></div></div><input aria-hidden="true" type="hidden" name="b_3e38430549570438cbc8b7513_57d9eeea29" value=""><button type="submit" name="subscribe" id="mc-embedded-subscribe">Subscribe</button></form></div><!--End mc_embed_signup-->
