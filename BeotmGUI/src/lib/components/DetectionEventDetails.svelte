<script lang="ts">
  import type { DetectionEvent } from '$lib/schemas/detection-events';

  let { selectedEvent = $bindable() }: { selectedEvent: DetectionEvent } = $props();
</script>

<div
  class="border-base-300 bg-base-100 flex flex-1 flex-col overflow-hidden rounded-xl border-1 p-2"
>
  <div>{selectedEvent.DateAndTime.toDateString()}</div>
  <div>{selectedEvent.Version}</div>
</div>
