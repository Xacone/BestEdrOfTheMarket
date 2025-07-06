<script lang="ts">
  import LetterText from '@lucide/svelte/icons/letter-text';
  import Binary from '@lucide/svelte/icons/binary';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import SquareFunction from '@lucide/svelte/icons/square-function';
  import BowArrow from '@lucide/svelte/icons/bow-arrow';
  import Target from '@lucide/svelte/icons/target';

  // TODO: move fetching logic at the page level or as a util
  // Use svelte stores to propagate data between components ?
  // (probably simpler): using child props
  import { DetectionEventSchema, type DetectionEvent } from '$lib/schemas/detection-events';

  let detectedEvents: DetectionEvent[] = $state([]);
  setInterval(async () => {
    const data = await (await fetch('http://127.0.0.1:8000/events')).json();
    const events = DetectionEventSchema.array().parse(data);
    events.forEach((receivedEvent) => detectedEvents.push(receivedEvent));
    detectedEvents.sort((evt1, evt2) => evt1.DateAndTime.getTime() - evt2.DateAndTime.getTime());
  }, 2000);

  let displayId = $state(false);
</script>

<!-- <th>Detection Time</th>
<th>Level</th>
<th>Global defensive method</th>
<th>Origin process</th>
<th>Victim process</th> -->

<div class="border-base-300 flex w-125 flex-1 flex-col overflow-hidden rounded-xl border-1">
  <div class="bg-base-200 p-2">
    TODO: sort options
    <button
      class="btn btn-square"
      onclick={() => {
        displayId = !displayId;
      }}
    >
      <label class="swap swap-rotate">
        <input type="checkbox" bind:checked={displayId} disabled />
        <LetterText class="swap-off h-7 w-7" strokeWidth="0.7"></LetterText>
        <Binary class="swap-on h-7 w-7" strokeWidth="0.7"></Binary>
      </label>
    </button>
  </div>
  <ul class="flex-1 overflow-y-scroll">
    {#each detectedEvents as evt, i}
      {#if i === 0 || evt.DateAndTime.toDateString() !== detectedEvents[i - 1].DateAndTime.toDateString()}
        <li
          class="bg-base-100 border-b-base-300 sticky top-0 border-b-1 p-0.5 text-right font-semibold"
        >
          {evt.DateAndTime.toLocaleDateString()}
        </li>
      {/if}
      <li class="border-b-base-300 hover:bg-base-200 flex w-full cursor-pointer border-b-1 p-2">
        <div class="w-full">
          <div class="flex gap-2">
            <div>{evt.DateAndTime.toLocaleTimeString()}</div>
            <div class="badge badge-{evt.Level.replace('Critical', 'Error').toLowerCase()}">
              {evt.Level}
            </div>
            <div class="flex">
              <span class="font-semibold">
                <!-- <BowArrow class="h-5 w-5" strokeWidth="0.7"></BowArrow> -->
                {displayId ? evt.OriginPID : evt.OriginProcess}
              </span>
              <ChevronRight class="h-7" strokeWidth="1"></ChevronRight>
              <span>
                <!-- <Target class="h-5 w-5" strokeWidth="0.7"></Target> -->
                {displayId ? evt.TargetPID : evt.VictimProcess}
              </span>
            </div>
          </div>
          <div class="flex flex-col gap-2 pt-1">
            <div class="flex items-center">
              <SquareFunction class="h-5 w-5" strokeWidth="0.7"></SquareFunction> :
              {displayId ? evt.GlobalDefensiveMethodId : evt.GlobalDefensiveMethod}
            </div>
            <div class="flex items-center">
              <ShieldCheck class="h-5 w-5" strokeWidth="0.7"></ShieldCheck> :
              {evt.InvolvedYaraRule}
            </div>
          </div>
        </div>
      </li>
    {/each}
  </ul>
  <div class="bg-base-200 p-2">TODO: filter options</div>
</div>
