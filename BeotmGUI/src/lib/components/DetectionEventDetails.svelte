<script lang="ts">
  import {type DetectionEvent, CodeInjectionInfoSchema} from '$lib/schemas/detection-events';
  import { t } from 'svelte-i18n'
  import ChevronsLeft from '@lucide/svelte/icons/chevrons-left';
  import ClipboardCopy from '@lucide/svelte/icons/clipboard-copy';
  import Check from '@lucide/svelte/icons/check';
  import X from '@lucide/svelte/icons/x';
  import {alertStore} from "$lib/components/alert/alert-manager";

  let { selectedEvent = $bindable() }: { selectedEvent: DetectionEvent | null } = $props();

  async function copyText() {
    try {
      await navigator.clipboard.writeText(selectedEvent!.OriginProcessImagePath);
      alertStore.send($t('event_details.success_copy_path'), 3000, 'success');
    } catch (err) {
      console.error($t('event_details.error_copy_path'), err);
      alertStore.send($t('event_details.error_copy_path'), 3000, 'error');
    }
  }
</script>

<div class="border-base-300 bg-base-100 flex flex-1 flex-col overflow-hidden rounded-xl border-1 p-2">
  {#if selectedEvent !== null}

    <div id="tool-row">
      <!--TODO Better style when hoovering buttons-->
      <button id="close-panel" onclick="{() => selectedEvent = null}" class="cursor-pointer"
              title="{ $t('event_details.tooltip.close') }">
        <ChevronsLeft/>
      </button>
      <button id="close-panel" onclick="{() => copyText()}" class="cursor-pointer"
              title="{ $t('event_details.tooltip.copy_path') }">
        <ClipboardCopy/>
      </button>
    </div>

    <div id="header">
      <div class="flex align-items-center">
        <h1 class="font-bold mr-3">{ selectedEvent.GlobalDefensiveMethod }</h1>
        <div class="badge badge-md badge-{selectedEvent.Level.replace('Critical', 'Error').toLowerCase()}">
          {selectedEvent.Level}
        </div>
      </div>
      <p>{ selectedEvent.DateAndTime.toDateString() }</p>
    </div>

    <div id="process-infos" class="flex mt-5">
      <div id="origin-process" class="width-1/2">
        <p class="font-semibold">Origin Process:</p>
        <div class="pl-5">
          <li>
            { selectedEvent.OriginProcess+ $t('event_details.pid', {values : {pid: selectedEvent.OriginPID}}) }
          </li>
          <li>
            { selectedEvent.OriginProcessImagePath }
          </li>
        </div>
      </div>
      <div id="victim-process" class="width-1/2 ml-3">
        <p class="font-semibold">Victim Process:</p>
        <div class="pl-5">
          <li>
            { selectedEvent.VictimProcess+ $t('event_details.pid', {values : {pid: selectedEvent.TargetPID}}) }
          </li>
        </div>
      </div>
    </div>

    <div id="other-infos" class="mt-5">
      <div id="yara-rule" class="flex">
        <p class="font-semibold">{ $t('event_details.yara_rule') }</p>
        <p>{ selectedEvent.InvolvedYaraRule }</p>
      </div>
      <div id="code-injection" class="flex mt-2">
        <label title={selectedEvent.isCodeInjection ? $t('label.yes') : $t('label.no')} class="flex">
          { $t('event_details.is_code_injection') }
          {#if selectedEvent.isCodeInjection}
            <Check/>
          {:else}
            <X/>
          {/if}
        </label>
      </div>
    </div>

    <div id="specific-infos" class="mt-5">
      {#each selectedEvent.SpecificEventsInfo as info, i}
        <!-- TODO better display because [Object] is not very explicit -->
        <p>{ i + ' : ' + info }</p>
      {/each}
    </div>
  {:else}
    <p>{ $t('event_details.waiting') }</p>
  {/if}
</div>