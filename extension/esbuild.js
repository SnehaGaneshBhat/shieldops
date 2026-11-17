const esbuild = require('esbuild');
const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');

async function main() {
  const ctx = await esbuild.context({
    entryPoints: {
      extension: 'src/extension.ts',
      api: 'src/api.ts',
      backend: 'src/backend.ts',
      diagnostics: 'src/diagnostics.ts',
      panel: 'src/panel.ts'
    },
    bundle: true,
    format: 'cjs',
    platform: 'node',
    target: 'node18',
    outdir: 'dist',
    external: ['vscode'],
    minify: production,
    sourcemap: !production,
    logLevel: 'info'
  });
  if (watch) await ctx.watch(); else { await ctx.rebuild(); await ctx.dispose(); }
}

main().catch((err) => { console.error(err); process.exit(1); });
