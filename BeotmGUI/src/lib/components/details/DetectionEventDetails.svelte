<script lang="ts">
  import { t } from 'svelte-i18n';
  import CircleX from '@lucide/svelte/icons/circle-x';

  import { LevelBadge } from '$lib/schemas/graphical-event';

  import { getEvents } from '$lib/logic/events-management.svelte';
  import MainInfo from './MainInfo.svelte';
  import SpecificInfo from './SpecificInfo.svelte';
  import OriginTarget from './OriginTarget.svelte';

  const events = getEvents();
</script>

<div class="border-base-300 bg-base-100 flex flex-1 flex-col overflow-auto rounded-xl border-1">
  {#if events.selected !== null}
    <div>
      <div class="bg-base-100 sticky top-0 flex gap-2 p-2">
        <button
          onclick={() => (events.selected = null)}
          class="btn btn-sm btn-circle btn-ghost"
          title={$t('event_details.tooltip.close')}
        >
          <CircleX strokeWidth="0.7" />
        </button>
        <header class="align-items-center flex gap-2">
          <div class="badge badge-lg {LevelBadge[events.selected.Level]}">
            {events.selected.Level}
          </div>
          <div>{events.selected.DateAndTime.toLocaleString()}</div>
        </header>
      </div>
      <div class="flex flex-col gap-5 p-2">
        <MainInfo selected={events.selected}></MainInfo>
        <OriginTarget selected={events.selected}></OriginTarget>
        <SpecificInfo selected={events.selected}></SpecificInfo>
      </div>
    </div>
  {:else}
    <p class="p-2">{$t('event_details.waiting')}</p>
  {/if}
</div>
