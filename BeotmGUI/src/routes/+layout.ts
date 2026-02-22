// For simplicity sake, this app is client only (no ssr).
export const ssr = false;
export const prerender = true;

import type { LayoutLoad } from './$types';

export const load: LayoutLoad = () => {
  // static config should go here
  return {};
};
