export interface AppNotification {
  message: string;
  level: 'info' | 'success' | 'warning' | 'error';
  remove: boolean;
}
