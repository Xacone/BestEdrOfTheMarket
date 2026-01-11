/**
 * Utility file where event properties
 * are explicitly mapped to DaisyUI classes.
 */

import type { DetectionEvent } from './detection-events';
import type { AppNotification } from './notification';

export const LevelBadge: Record<DetectionEvent['Level'], string> = {
  Critical: 'badge-error',
  Info: 'badge-info',
  Warning: 'badge-warning',
};

export const LevelAlert: Record<DetectionEvent['Level'] | AppNotification['level'], string> = {
  Critical: 'alert-error',
  Info: 'alert-info',
  Warning: 'alert-warning',
  error: 'alert-error',
  success: 'alert-success',
  info: 'alert-info',
  warning: 'alert-warning',
};
