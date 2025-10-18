import { DetectionEventSchema, type DetectionEvent } from '$lib/schemas/detection-events';
import { createContext } from 'svelte';

export class EventsManager {
  loaded: DetectionEvent[] = $state([]);
  selected: DetectionEvent | null = $state(null);

  private poll = () => {
    return setInterval(async () => {
      const data = await (await fetch('http://127.0.0.1:8000/events')).json();
      const events = DetectionEventSchema.array().parse(data);
      events.forEach((receivedEvent) => this.loaded.push(receivedEvent));
      this.loaded.sort((evt1, evt2) => evt1.DateAndTime.getTime() - evt2.DateAndTime.getTime());
    }, 2000);
  };

  constructor() {
    this.poll();
  }

  deselect = () => {
    this.selected = null;
  };
}

export const [getEvents, initEventManager] = createContext<EventsManager>();
