<script lang="ts">
    import { onDestroy } from 'svelte';
    import { alertStore, type Alert } from '$lib/components/alert/alert-manager';
    import { fly } from 'svelte/transition';
    import {} from 'daisyui/colors/properties.css';

    let alert: Alert | null = null;

    const unsubscribe = alertStore.subscribe(value => alert = value);

    onDestroy(() => unsubscribe());
</script>

{#if alert}
    <div class="fixed top-4 z-index=2 left-6/12 -translate-x-1/2 p-2 bg-{alert.severity} rounded-lg" role="alertdialog"
         in:fly={{ y: -20, duration: 200 }} out:fly={{ y: 20, duration: 200 }}>
        {alert.message}
    </div>
{/if}
