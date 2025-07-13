<script lang="ts">
  import { type DetectionEvent, CodeInjectionInfoSchema } from '$lib/schemas/detection-events';
  import { t } from 'svelte-i18n';
  import ChevronsLeft from '@lucide/svelte/icons/chevrons-left';

  import CopyText from './CopyText.svelte';
  import type { AppNotification } from '$lib/schemas/notification';

  let {
    selectedEvent = $bindable(),
    notification = $bindable(),
  }: { selectedEvent: DetectionEvent | null; notification: AppNotification | null } = $props();
</script>

<div
  class="border-base-300 bg-base-100 flex flex-1 flex-col overflow-hidden rounded-xl border-1 p-2"
>
  {#if selectedEvent !== null}
    <div id="tool-row">
      <!--TODO Better style when hoovering buttons-->
      <button
        id="close-panel"
        onclick={() => (selectedEvent = null)}
        class="cursor-pointer"
        title={$t('event_details.tooltip.close')}
      >
        <ChevronsLeft />
      </button>
    </div>

    <div id="header">
      <div class="align-items-center flex">
        <h1 class="mr-3 font-bold">{selectedEvent.GlobalDefensiveMethod}</h1>
        <div
          class="badge badge-md badge-{selectedEvent.Level.replace(
            'Critical',
            'Error',
          ).toLowerCase()}"
        >
          {selectedEvent.Level}
        </div>
      </div>
      <p>{selectedEvent.DateAndTime.toDateString()}</p>
    </div>

    <div id="process-infos" class="mt-5 flex">
      <div id="origin-process" class="width-1/2">
        <p class="font-semibold">Origin Process</p>
        <div class="pl-5">
          <li>
            {$t('event_details.pid')}:
            <CopyText text={selectedEvent.OriginPID + ''} bind:notification></CopyText>
          </li>
          <li>
            Name:
            <CopyText text={selectedEvent.OriginProcess} bind:notification></CopyText>
          </li>
          <li>
            Path: <CopyText text={selectedEvent.OriginProcessImagePath} bind:notification
            ></CopyText>
          </li>
        </div>
      </div>
      <div id="victim-process" class="width-1/2 ml-3">
        <p class="font-semibold">Victim Process</p>
        <div class="pl-5">
          <li>
            {$t('event_details.pid')}:
            <CopyText text={selectedEvent.TargetPID + ''} bind:notification></CopyText>
          </li>
          <li>
            Name: <CopyText text={selectedEvent.VictimProcess} bind:notification></CopyText>
          </li>
        </div>
      </div>
    </div>

    <div id="other-infos" class="mt-5">
      <div id="yara-rule">
        <p class="font-semibold">{$t('event_details.yara_rule')}</p>
        <p>{selectedEvent.InvolvedYaraRule}</p>
      </div>
      <div id="code-injection" class="mt-2 flex">
        {$t('event_details.is_code_injection')}
        <CopyText text={selectedEvent.isCodeInjection + ''} bind:notification></CopyText>
      </div>
    </div>

    <div id="specific-infos" class="mt-5">
      {#each selectedEvent.SpecificEventsInfo as info, i}
        <!-- TODO better display because [Object] is not very explicit -->
        <p>{i + ' : ' + info}</p>
      {/each}
    </div>
  {:else}
    <p>{$t('event_details.waiting')}</p>
  {/if}
</div>
