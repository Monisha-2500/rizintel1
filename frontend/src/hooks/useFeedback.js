import { useState, useCallback } from 'react';
import { submitAnalystFeedback, getFeedbackForFinding } from '../services/findingsService';

export function useFeedback(findingId) {
  const [history,    setHistory]    = useState(() => getFeedbackForFinding(findingId));
  const [submitting, setSubmitting] = useState(false);
  const [error,      setError]      = useState(null);

  const submit = useCallback(async (decision, reason = '') => {
    setSubmitting(true);
    setError(null);
    try {
      await submitAnalystFeedback(findingId, decision, reason);
      setHistory(getFeedbackForFinding(findingId));
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }, [findingId]);

  return { history, submit, submitting, error };
}
