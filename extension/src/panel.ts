const nested =
  it.explanation && typeof it.explanation === 'object' && !Array.isArray(it.explanation)
    ? it.explanation
    : {};

const plainExplanation = nested.plain_explanation ?? it.plain_explanation;
const whyItMatters = nested.why_it_matters ?? it.why_it_matters;
const recommendedActions = nested.recommended_actions ?? it.recommended_actions;
const itemLimitations = nested.limitations ?? it.limitations;

const actions = Array.isArray(recommendedActions)
  ? recommendedActions.map((action) => `<li>${esc(action)}</li>`).join('')
  : '';

const sourceType = it.explanation_source ?? reportSource;
const source =
  sourceType === 'llm' || sourceType === 'llm_validated'
    ? 'AI explanation · checked against findings'
    : 'Template explanation';
