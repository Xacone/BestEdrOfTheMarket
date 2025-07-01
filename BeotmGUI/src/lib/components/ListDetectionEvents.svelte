<script lang="ts">
  let detectionEvents: any[] = $state([]);
  setInterval(async () => {
    const receivedEvents = await (await fetch('http://127.0.0.1:8000/events')).json();
    detectionEvents = [receivedEvents];
  }, 2000);

  // Use svelte stores to propagate data between components ?
</script>

<div>
  {JSON.stringify(detectionEvents, null, 2)}
</div>
