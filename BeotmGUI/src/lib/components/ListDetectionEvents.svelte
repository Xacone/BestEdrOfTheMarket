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

<div class="overflow-x-auto">
  <table class="table">
    <thead>
      <tr>
        <th>Detection Time</th>
        <th>Level</th>
        <th>Global defensive method</th>
        <th>Origin process</th>
        <th>Victim process</th>
      </tr>
    </thead>
    <tbody>
      {#each detectedEvents as evt}
        <tr>
          <td>
            {evt.DateAndTime.toLocaleString()}
          </td>
          <td>
            {#if evt.Level === 'Critical'}
              <div class="badge badge-outline badge-error">Critical</div>
            {:else if evt.Level === 'Warning'}
              <div class="badge badge-outline badge-warning">Warning</div>
            {:else}
              <div class="badge badge-outline badge-info">Info</div>
            {/if}
          </td>
          <td>
            <div class="badge badge-neutral">{evt.GlobalDefensiveMethod}</div>
          </td>
          <td>
            <span class="badge badge-primary">{evt.OriginProcess}</span>
          </td>
          <td>
            <span class="badge badge-secondary">{evt.VictimProcess}</span>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
