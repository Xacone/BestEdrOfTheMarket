<script lang="ts">
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
</script>

<!-- <th>Detection Time</th>
<th>Level</th>
<th>Global defensive method</th>
<th>Origin process</th>
<th>Victim process</th> -->
<div class="bg-base-300 w-200 flex-1 overflow-hidden rounded-xl pb-10">
  <div class="bg-base-200 p-2">Detected events</div>
  <ul class="h-full overflow-y-scroll">
    {#each detectedEvents as evt, i}
      {#if i === 0 || evt.DateAndTime.toDateString() !== detectedEvents[i - 1].DateAndTime.toDateString()}
        <li class="bg-base-300 sticky top-0 z-10 p-2">{evt.DateAndTime.toLocaleDateString()}</li>
      {/if}
      <li class="flex pr-5 pl-5">
        {evt.DateAndTime.getHours()}:{evt.DateAndTime.getMinutes()}
        {evt.Level}
        {evt.GlobalDefensiveMethod}
        {evt.OriginProcess}
        {evt.VictimProcess}
        {evt.InvolvedYaraRule}
      </li>
    {/each}
  </ul>
</div>
