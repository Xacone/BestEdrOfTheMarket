// Declares detectedEvents as a state.
// To keep a clear parent-child logic
// only import it once at the root, and spread it to the children,
// see more on https://svelte.dev/docs/svelte/$props

import { DetectionEventSchema, type DetectionEvent } from '$lib/schemas/detection-events';

export let detectedEvents: DetectionEvent[] = $state([]);

setInterval(async () => {
  const data = await (await fetch('http://127.0.0.1:8000/events')).json();
  const events = DetectionEventSchema.array().parse(data);
  events.forEach((receivedEvent) => detectedEvents.push(receivedEvent));
  detectedEvents.sort((evt1, evt2) => evt1.DateAndTime.getTime() - evt2.DateAndTime.getTime());
}, 2000);
