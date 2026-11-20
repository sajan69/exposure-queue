import { ZodError } from 'zod';
import { ImportError } from './findings.js';
import { FindingConflict, StaleReview } from './store.js';

export class RouteNotFound extends Error {}

export function httpFailure(error: unknown): { status: number; error: string } {
  if (error instanceof RouteNotFound)
    return { status: 404, error: 'Unknown API route' };
  if (error instanceof StaleReview || error instanceof FindingConflict) {
    return {
      status: 409,
      error: 'Workspace changed or finding conflicts; review again',
    };
  }
  if (error instanceof ZodError || error instanceof ImportError) {
    return { status: 400, error: 'Invalid request' };
  }
  return { status: 500, error: 'Request failed' };
}
