<script lang="ts">
  import { login } from "./lib/api";

  let username = $state("");
  let password = $state("");
  let submitting = $state(false);
  let errorMsg = $state("");
  let showPw = $state(false);

  async function onSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (submitting) return;
    errorMsg = "";
    submitting = true;
    try {
      const r = await login(username.trim(), password);
      window.location.assign(r.redirect || "/project");
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : "Login failed.";
      password = "";
    } finally {
      submitting = false;
    }
  }
</script>

<main class="min-h-screen flex items-center justify-center px-4 py-12 bg-gradient-to-br from-slate-100 via-slate-50 to-kmitl-50">
  <section class="w-full max-w-md">
    <header class="mb-8 text-center">
      <div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-kmitl-500 text-white text-2xl font-bold shadow-md">
        Ω
      </div>
      <h1 class="mt-4 text-2xl font-semibold text-slate-900">Overleaf · IT KMITL</h1>
      <p class="mt-1 text-sm text-slate-500">Sign in with your KMITL IT directory account</p>
    </header>

    <form
      onsubmit={onSubmit}
      class="bg-white rounded-2xl shadow-sm ring-1 ring-slate-200 p-6 space-y-5"
      autocomplete="off"
      novalidate
    >
      <div>
        <label for="username" class="block text-sm font-medium text-slate-700">
          Username
        </label>
        <input
          id="username"
          name="username"
          type="text"
          bind:value={username}
          required
          autocomplete="username"
          autocapitalize="none"
          spellcheck="false"
          disabled={submitting}
          class="mt-1 block w-full rounded-lg border-slate-300 shadow-sm
                 focus:border-kmitl-500 focus:ring focus:ring-kmitl-500/30
                 disabled:bg-slate-50 text-slate-900 px-3 py-2 border"
          placeholder="e.g. johndoe"
        />
      </div>

      <div>
        <div class="flex items-center justify-between">
          <label for="password" class="block text-sm font-medium text-slate-700">
            Password
          </label>
          <button
            type="button"
            class="text-xs text-kmitl-600 hover:text-kmitl-700 select-none"
            onclick={() => (showPw = !showPw)}
            tabindex="-1"
          >
            {showPw ? "Hide" : "Show"}
          </button>
        </div>
        <input
          id="password"
          name="password"
          type={showPw ? "text" : "password"}
          bind:value={password}
          required
          autocomplete="current-password"
          disabled={submitting}
          class="mt-1 block w-full rounded-lg border-slate-300 shadow-sm
                 focus:border-kmitl-500 focus:ring focus:ring-kmitl-500/30
                 disabled:bg-slate-50 text-slate-900 px-3 py-2 border"
          placeholder="••••••••"
        />
      </div>

      {#if errorMsg}
        <div
          role="alert"
          class="rounded-md bg-rose-50 ring-1 ring-rose-200 px-3 py-2 text-sm text-rose-700"
        >
          {errorMsg}
        </div>
      {/if}

      <button
        type="submit"
        disabled={submitting || !username || !password}
        class="w-full inline-flex justify-center items-center gap-2 rounded-lg
               bg-kmitl-500 hover:bg-kmitl-600 active:bg-kmitl-700
               disabled:bg-slate-300 disabled:cursor-not-allowed
               text-white font-medium px-4 py-2.5 transition-colors shadow-sm"
      >
        {#if submitting}
          <svg class="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"/>
          </svg>
          Signing in…
        {:else}
          Sign in
        {/if}
      </button>
    </form>

    <footer class="mt-6 text-center text-xs text-slate-500">
      Authorized use only · Sessions are logged ·
      <a href="https://www.kmitl.ac.th/it" class="text-kmitl-600 hover:underline">IT KMITL</a>
    </footer>
  </section>
</main>
