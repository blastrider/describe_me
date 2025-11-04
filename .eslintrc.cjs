module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
  },
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  rules: {
    'no-eval': 'error',
    'no-new-func': 'error',
    'no-restricted-syntax': [
      'error',
      {
        selector: "MemberExpression[property.name='innerHTML']",
        message: "Éviter innerHTML ; utiliser textContent ou des APIs DOM sûres.",
      },
      {
        selector: "CallExpression[callee.name='eval']",
        message: "eval est interdit (risque d'exécution arbitraire).",
      },
      {
        selector: "NewExpression[callee.name='Function']",
        message: "new Function est interdit (risque d'exécution arbitraire).",
      },
    ],
  },
};
