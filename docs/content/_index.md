---
title: OpenRun
layout: hextra-home
cascade:
  images: ["/openrun_small.png"]
---

<div class="hx:mb-4" style="background: #277A9F; background: linear-gradient(180deg, #277A9F, #359ece); color: transparent; background-clip: text; -webkit-background-clip: text;">
{{< hextra/hero-headline >}}
  Internal Tools Deployment Platform
{{< /hextra/hero-headline >}}
</div>

<div class="hx:mb-6">
{{< hextra/hero-subtitle >}}
  Internal tools deployment made easy.&nbsp;<br class="hx:sm:block hx:hidden"/>Deploy web apps declaratively, on a single-node or on Kubernetes.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx:mb-4 hx:flex hx:flex-wrap hx:gap-2">
{{< hextra/hero-button style="border-radius: 8px;" text="Get Started" link="docs/quickstart" >}}
{{< hextra/hero-button style="border-radius: 8px; padding: 12px 40px;" text="Demo" link="https://apps.demo.clace.io" >}}
</div>

{{< hextra/feature-grid >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="What is OpenRun?" icon="information-circle" subtitle="OpenRun™ is a web app deployment platform, with a focus on deploying internal tools. OpenRun makes it easy to declaratively deploy containerized web apps. OpenRun can deploy apps on a single-node or onto a Kubernetes cluster.<br><br>OpenRun provides declarative GitOps based blue-green deployment, OAuth/OIDC/SAML access controls, TLS certs & secrets management. OpenRun has RBAC and auditing features for teams to securely deploy internal tools.<br><br> " style="background: radial-gradient(ellipse at 50% 80%,rgba(89, 67, 7, 0.15),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="OpenRun Features" icon="lightning-bolt" subtitle="Some of the unique features of OpenRun are:<br><br>➣ Create and manage apps declaratively<br>➣ Easily upgrade from single-node to K8S <br>➣ Domain based or path based routing, with auto-TLS<br>➣ OAuth/OpenID/SAML/Cert based auth<br>➣ RBAC for admin operation and for app access<br>➣ Scales idle apps down to zero<br>➣ Staged deployment, for code and config changes<br>➣ Atomic (all or nothing) updates across apps" style="background: radial-gradient(ellipse at 50% 80%,rgba(89, 67, 7, 0.15),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore --> {{< hextra/feature-card title="How it Works" icon="beaker" subtitle="OpenRun is a single binary, which implements an webserver and application server. For single-node install, Docker/Podman is the only external dependency.<br><br>OpenRun supports:<br>➣ Single node deployment using SQLite database<br>➣ Kubernetes deployment with Postgres for metadata<br>➣ Linux, OSX and Windows platforms.<br>➣ Builds app images, runs continuous deployment and manages auth and request routing across apps" style="background: radial-gradient(ellipse at 50% 80%,rgba(89, 67, 7, 0.15),hsla(0,0%,100%,0));" >}}

{{< /hextra/feature-grid >}}

<div style="height: 20px;"></div>

<div style="position: relative; width: 100vw; margin-left: calc(-50vw + 50%); background: #007700; color: white; justify-content: center; box-sizing: border-box; padding: 25px; font-family: 'Inter', 'Segoe UI', 'Helvetica Neue', 'Roboto', 'Arial', sans-serif;">
<div style="max-width: 800px; width: 100%; margin: 0 auto; padding: 1rem;">

<div style="font-weight: bold; margin-bottom: 20px; text-align: center;font-size: 24px; color: mintcream;">Installation</div>

<div style="position: relative;">
<div style="font-weight: bold; margin-bottom: 10px; color: lightgray;">Install OpenRun:</div>
<div style="padding-inline: 10px; padding-top: 5px; padding-bottom: 20px; font-size: 14px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;" id="code1">
curl -sSL https://openrun.dev/install.sh | sh
</div>
<button title="Copy" style="position: absolute; top: 5px; right: 5px; padding: 10px 10px 1px 10px; font-size: 14px; cursor: pointer;" onclick="copyCode('code1', this)">⧉</button>
</div>

<div style="position: relative;">
<div style="font-weight: bold; margin-bottom: 10px; color: lightgray;">Start OpenRun server (in a new window):</div>
<div style="padding-inline: 10px; padding-top: 5px; padding-bottom: 20px; font-size: 14px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;" id="code2">
openrun server start &
</div>
<button title="Copy" style="position: absolute; top: 5px; right: 5px;  padding: 10px 10px 1px 10px; font-size: 14px; cursor: pointer;" onclick="copyCode('code2', this)">⧉</button>
</div>

<div style="font-weight: bold; margin-top: 20px; margin-bottom: 20px; text-align: center;font-size: 24px; color: mintcream;">GitOps in One Command</div>

<div style="position: relative;">
<div style="font-weight: bold; margin-bottom: 10px; color: lightgray;">Schedule a sync:</div>
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
<div style="font-weight: bold; margin-bottom: 16px; font-size: 22px;">Sample OpenRun Config</div>
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
{{< hextra/feature-card title="Container management" link="docs/quickstart/#containerized-applications" subtitle="Declaratively build and deploy containerized web apps, with Docker/Podman or Kubernetes."  icon="docker" style="background: radial-gradient(ellipse at 50% 80%,rgba(102, 89, 186, 0.25),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Declarative GitOps" link="docs/quickstart/#lifecycle-with-git" subtitle="Staged deployments and preview environments; GitOps With GitHub/GitLab, cloud or on-prem"  icon="github" style="background: radial-gradient(ellipse at 50% 80%,rgba(102, 89, 186, 0.25),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Secrets Management" link="/docs/configuration/secrets/" subtitle="Manage secrets with AWS Secrets Manager, Vault or Kubernetes."  icon="shield-exclamation" style="background: radial-gradient(ellipse at 50% 80%,rgba(102, 89, 186, 0.15),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Scale down to zero" link="/docs/container/overview/" subtitle="Apps are initialized lazily, on demand and scale down to zero when idle."  icon="pause" style="background: radial-gradient(ellipse at 50% 80%,rgba(102, 89, 186, 0.25),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Zero-config dev env setup" link="/docs/applications/overview/#apply-command" subtitle="Easily setup dev environment with zero config required."  icon="check" style="background: radial-gradient(ellipse at 50% 80%,rgba(102, 89, 186, 0.25),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Flexible Auth" link="/docs/configuration/authentication/" subtitle="OAuth/OpenID/SAML/Client-cert based auth, with full RBAC support"  icon="shield-check" style="background: radial-gradient(ellipse at 50% 80%,rgba(102, 89, 186, 0.25),hsla(0,0%,100%,0));" >}}

{{< /hextra/feature-grid >}}

<div style="height: 20px;"></div>

{{< hextra/feature-grid >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Comparison with other self-hosted solutions" icon="zoom-in" subtitle="Compared to solutions like Coolify, Kamal, Dokku etc, OpenRun has:<br />➣ **Declarative GitOps** interface, for code and for config. New apps can be added through config updates in git. **No ClickOps, No manual deployments**<br/>➣ Scale idle apps down to zero <br />➣ Single binary, Docker/Podman or Kubernetes is only dependency, does not depend on a third party webserver like Traefik/Nginx<br/><br/>OpenRun supports enterprise features needed by teams, like OAuth/OIDC/SAML with RBAC and audit logs. OpenRun is built as a self-hosted Google Cloud Run/AWS App Runner alternative as against full PaaS solution. OpenRun does not support deploying auxiliary services like databases and there is no Docker Compose support. " style="background: radial-gradient(ellipse at 50% 80%,rgba(89, 67, 7, 0.15),hsla(0,0%,100%,0));" >}}

<!-- prettier-ignore -->
{{< hextra/feature-card title="Comparison with DIY on Kubernetes" icon="cog" subtitle="Running OpenRun on Kubernetes gives you the benefits of Kubernetes without the pain. OpenRun provides:<br/>➣ Unified interface as against glueing together services like Jenkins for builds, ArgoCD/FluxCD for CD, IDP for app management etc.<br/>➣ Simple declarative config, **no YAML files, no webserver DSLs**.<br/>➣ Support for setting up auth policies using RBAC.<br/><br/>Compared to **Knative**, OpenRun has a much simpler config without requiring YAML files. Resource usage is lower with OpenRun since apps are loaded lazily, on the first API call. OpenRun app versions are maintained in the metadata database, reducing Kubernetes resources created. Knative requires an external build system and does not support auth for apps." style="background: radial-gradient(ellipse at 50% 80%,rgba(89, 67, 7, 0.15),hsla(0,0%,100%,0));" >}}

{{< hextra/feature-card title="Common use cases" icon="users" subtitle="OpenRun can be used by teams to:<br/>➣ For operations teams to provide an easy on-ramp to Kubernetes for dev teams<br/>➣  Deploy web apps with zero config required for most common frameworks like **Streamlit/Gradio/FastHTML/NiceGUI** etc.<br />➣ Replace Jenkins/Rundeck jobs, using OpenRun Actions for **automating operational scripts**<br/>➣ Expose web apps for internal REST APIs, replacing manual curl commands<br><br>While the auth and auditing features of OpenRun are built for use by teams, OpenRun can also be used by individuals for:<br/>➣ Zero-config dev env setup locally<br/>➣ Host web apps shared with friends and family, using OAuth" style="background: radial-gradient(ellipse at 50% 80%,rgba(89, 67, 7, 0.15),hsla(0,0%,100%,0));" >}}

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
