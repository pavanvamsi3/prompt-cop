const { HfInference } = require('@huggingface/inference');

// Use a zero-shot classification model for prompt injection detection
const MODEL = process.env.HF_MODEL_ID || 'facebook/bart-large-mnli';

/**
 * Detect potential prompt injection using Hugging Face Inference service.
 * Requires HF_ACCESS_TOKEN environment variable for authenticated access.
 * @param {string} text - Text content to analyze
 * @returns {Promise<{score: number}|null>} result if classified as prompt injection
 */
async function detectPromptInjection(text) {
  try {
    const accessToken = process.env.HF_ACCESS_TOKEN;
    const hf = new HfInference(accessToken || undefined);
    const result = await hf.zeroShotClassification({
      model: MODEL,
      inputs: [text],
      parameters: { candidate_labels: ['prompt injection', 'safe'] }
    });
    // Handle array response format
    const classification = Array.isArray(result) ? result[0] : result;
    if (!classification || !classification.labels) return null;
    
    const idx = classification.labels.findIndex(l => l.toLowerCase() === 'prompt injection');
    if (idx !== -1 && classification.scores[idx] >= 0.5) {
      return { score: classification.scores[idx] };
    }
  } catch (err) {
    console.error('Hugging Face inference failed:', err.message);
  }
  return null;
}

module.exports = { detectPromptInjection };
