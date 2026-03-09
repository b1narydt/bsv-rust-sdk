import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync, statSync } from 'node:fs'
import { join, basename } from 'node:path'

function usage () {
  console.log(`Usage: node benchmarks/compare.js [options]

Options:
  --ts-dir <dir>     Directory containing TS JSON result files (default: benchmarks/results)
  --rust-dir <dir>   Criterion output directory (default: rust-sdk/target/criterion)
  --output <file>    Output report path (default: benchmarks/results/comparison-report.md)
  --help             Show this help message
`)
}

function parseArgs (argv) {
  const args = {
    tsDir: 'benchmarks/results',
    rustDir: 'target/criterion',
    output: 'benchmarks/results/comparison-report.md'
  }
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case '--ts-dir':
        args.tsDir = argv[++i]
        break
      case '--rust-dir':
        args.rustDir = argv[++i]
        break
      case '--output':
        args.output = argv[++i]
        break
      case '--help':
        usage()
        process.exit(0)
    }
  }
  return args
}

function readCriterionResults (criterionDir) {
  const results = {}
  if (!existsSync(criterionDir)) {
    console.warn(`Warning: Criterion directory not found: ${criterionDir}`)
    return results
  }

  function walk (dir, prefix) {
    let entries
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }
    for (const entry of entries) {
      const fullPath = join(dir, entry)
      let stat
      try {
        stat = statSync(fullPath)
      } catch {
        continue
      }
      if (stat.isDirectory()) {
        // Check for estimates.json in new/ subdirectory
        const estimatesPath = join(fullPath, 'new', 'estimates.json')
        if (existsSync(estimatesPath)) {
          try {
            const data = JSON.parse(readFileSync(estimatesPath, 'utf-8'))
            const key = prefix ? `${prefix}/${entry}` : entry
            results[key] = {
              meanNs: data.mean.point_estimate,
              stddevNs: data.std_dev.point_estimate,
              medianNs: data.median.point_estimate
            }
          } catch (err) {
            console.warn(`Warning: Failed to parse ${estimatesPath}: ${err.message}`)
          }
        }
        // Recurse into subdirectories
        const nextPrefix = prefix ? `${prefix}/${entry}` : entry
        walk(fullPath, nextPrefix)
      }
    }
  }

  walk(criterionDir, '')
  return results
}

function readTsResults (jsonDir) {
  const allResults = []
  if (!existsSync(jsonDir)) {
    console.warn(`Warning: TS results directory not found: ${jsonDir}`)
    return allResults
  }

  const files = readdirSync(jsonDir).filter(f => f.endsWith('.json'))
  for (const file of files) {
    try {
      const data = JSON.parse(readFileSync(join(jsonDir, file), 'utf-8'))
      if (Array.isArray(data)) {
        allResults.push(...data)
      }
    } catch (err) {
      console.warn(`Warning: Failed to parse ${file}: ${err.message}`)
    }
  }
  return allResults
}

function generateReport (tsResults, rustResults, mappings) {
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ')
  const lines = []
  lines.push('# Benchmark Comparison Report')
  lines.push('')
  lines.push(`Generated: ${now}`)
  lines.push('')
  lines.push('| Benchmark | TS avg (ms) | Rust avg (ms) | Speedup | Status |')
  lines.push('|-----------|-------------|---------------|---------|--------|')

  let matched = 0
  let tsOnly = 0
  let rustOnly = 0
  let slower = 0

  for (const mapping of mappings) {
    const tsEntry = tsResults.find(r => r.name === mapping.tsName)
    const rustEntry = rustResults[mapping.rustKey]

    const tsMs = tsEntry ? tsEntry.average : null
    const rustMs = rustEntry ? rustEntry.meanNs / 1_000_000 : null

    const tsStr = tsMs != null ? tsMs.toFixed(4) : 'N/A'
    const rustStr = rustMs != null ? rustMs.toFixed(4) : 'N/A'

    let speedup = 'N/A'
    let status = '-'

    if (tsMs != null && rustMs != null && rustMs > 0) {
      const ratio = tsMs / rustMs
      speedup = ratio.toFixed(1) + 'x'
      if (ratio >= 0.8) {
        status = 'OK'
      } else {
        status = '**SLOWER**'
        slower++
      }
      matched++
    } else if (tsMs != null && rustMs == null) {
      status = 'Rust N/A'
      tsOnly++
    } else if (tsMs == null && rustMs != null) {
      status = 'TS N/A'
      rustOnly++
    }

    lines.push(`| ${mapping.label} | ${tsStr} | ${rustStr} | ${speedup} | ${status} |`)
  }

  lines.push('')
  lines.push('## Summary')
  lines.push('')
  lines.push(`- **Total mappings:** ${mappings.length}`)
  lines.push(`- **Matched (both sides):** ${matched}`)
  lines.push(`- **TS only:** ${tsOnly}`)
  lines.push(`- **Rust only:** ${rustOnly}`)
  if (slower > 0) {
    lines.push(`- **Rust slower than TS:** ${slower} (flagged with **SLOWER**)`)
  } else if (matched > 0) {
    lines.push(`- **All matched benchmarks:** Rust faster or equal`)
  }
  lines.push('')

  return lines.join('\n')
}

function main () {
  const args = parseArgs(process.argv)

  const mappingsPath = join('benchmarks', 'mappings.json')
  if (!existsSync(mappingsPath)) {
    console.error(`Error: mappings.json not found at ${mappingsPath}`)
    process.exit(1)
  }

  const mappings = JSON.parse(readFileSync(mappingsPath, 'utf-8'))
  console.log(`Loaded ${mappings.length} benchmark mappings`)

  const tsResults = readTsResults(args.tsDir)
  console.log(`Found ${tsResults.length} TS benchmark results`)

  const rustResults = readCriterionResults(args.rustDir)
  const rustCount = Object.keys(rustResults).length
  console.log(`Found ${rustCount} Rust Criterion results`)

  const report = generateReport(tsResults, rustResults, mappings)

  const outputDir = join(args.output, '..')
  mkdirSync(outputDir, { recursive: true })
  writeFileSync(args.output, report)
  console.log(`Report written to ${args.output}`)
}

main()
