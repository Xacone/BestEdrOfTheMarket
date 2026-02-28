import { createContext } from 'svelte';

export type ToastLevel = 'info' | 'success' | 'warning' | 'error';

export class ToastManager {
  notifications: {
    message: string;
    level: ToastLevel;
    timeout: number;
    id: string;
  }[] = $state([]);

  trigger = (notification: { message: string; level: ToastLevel }) => {
    const id: string = crypto.randomUUID();
    const timeout = setTimeout(() => this.remove(id), 2000);
    this.notifications.push({
      ...notification,
      timeout,
      id,
    });
  };

  remove = (id: string) => {
    const index = this.notifications.findIndex((n) => n.id === id);
    if (index >= 0) {
      clearTimeout(this.notifications[index].timeout);
      this.notifications.splice(index, 1);
    }
  };
}

export const [getToast, initToastManager] = createContext<ToastManager>();
