import { writable, type Writable } from 'svelte/store';

export interface Alert {
  message: string;
  duration: number;
  severity: 'info' | 'success' | 'warning' | 'error';
}

/**
 * Alert manager via a queue
 *
 * Add an alert using the “send” method with three parameters :
 *    - message : the content of the alert (an alert without text is not displayed)
 *    - duration : number of milliseconds during which the alert will remain displayed (default: 3000)
 *    - severity : type of alert : info / success / warning (default) / error
 */
function createAlertStore() {
  const queue: Writable<Alert[]> = writable([]);
  const currentAlert: Writable<Alert | null> = writable(null);

  const showNext = () => {
    queue.update((q) => {
      if (q.length === 0) {
        currentAlert.set(null);
        return q;
      } else {
        const alertDuration: number = q[0].duration;
        currentAlert.set(q[0]);
        setTimeout(() => {
          queue.update((q) => {
            q.shift();
            showNext();
            return q;
          });
        }, alertDuration);
        return q;
      }
    });
  };

  return {
    subscribe: currentAlert.subscribe,
    send: (message: string, duration: number = 3000, severity: 'info' | 'success' | 'warning' | 'error' = 'warning') => {
      if (message.length === 0) {
        const newAlert: Alert = { message, duration, severity };
        queue.update((q) => {
          return [...q, newAlert];
        });
        currentAlert.subscribe((current) => {
          if (!current) {
            showNext();
          }
        })();
      }
    },
  };
}

export const alertStore = createAlertStore();