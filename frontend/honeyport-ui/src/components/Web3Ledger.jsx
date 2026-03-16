import { useState, useEffect, useCallback } from 'react'
import { ethers } from 'ethers'
import { Link, RefreshCw, ExternalLink } from 'lucide-react'

// ── Minimal ABI (only the read functions we need) ──────────────────────────
const ABI = [
  "function recordCount() view returns (uint256)",
  "function getRecord(uint256 _id) view returns (string attackerIP, uint256 capturedAt, uint8 osintScore, string attackType, string ipfsCID, address reporter)",
  "function getLatestRecords(uint256 _n) view returns (uint256[])",
]

const CONTRACT_ADDR = import.meta.env.VITE_CONTRACT_ADDRESS ?? ''
const RPC_URL       = import.meta.env.VITE_RPC_URL          ?? 'https://rpc.sepolia.org'

// Pinata / IPFS gateway
const ipfsGateway = (cid) =>
  cid.startsWith('bafk-local-')
    ? `#local/${cid}`
    : `https://gateway.pinata.cloud/ipfs/${cid}`

const sepoliaExplorer = (tx) =>
  tx ? `https://sepolia.etherscan.io/tx/0x${tx}` : '#'

export default function Web3Ledger() {
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)
  const [count,   setCount]   = useState(null)

  const fetchFromChain = useCallback(async () => {
    if (!CONTRACT_ADDR) {
      // Fallback: load from backend /api/attacks/latest
      try {
        setLoading(true)
        const r = await fetch('/api/attacks/latest?n=10')
        const d = await r.json()
        setRecords(d.records ?? [])
        setCount(d.count ?? 0)
      } catch (e) {
        setError('API unavailable – ' + e.message)
      } finally {
        setLoading(false)
      }
      return
    }

    // Direct ethers.js call to Sepolia
    try {
      setLoading(true)
      setError(null)
      const provider = new ethers.JsonRpcProvider(RPC_URL)
      const contract = new ethers.Contract(CONTRACT_ADDR, ABI, provider)

      const totalBig  = await contract.recordCount()
      const total     = Number(totalBig)
      setCount(total)

      const N    = Math.min(total, 10)
      const ids  = await contract.getLatestRecords(N)

      const rows = await Promise.all(
        ids.map(async (id) => {
          const r = await contract.getRecord(id)
          return {
            record_id:   Number(id),
            attacker_ip: r.attackerIP,
            captured_at: Number(r.capturedAt),
            osint_score: Number(r.osintScore),
            attack_type: r.attackType,
            ipfs_cid:    r.ipfsCID,
            reporter:    r.reporter,
          }
        })
      )
      setRecords(rows)
    } catch (e) {
      setError('Chain read error: ' + e.message)
      // Fallback to API
      try {
        const r = await fetch('/api/attacks/latest?n=10')
        const d = await r.json()
        setRecords(d.records ?? [])
        setCount(d.count ?? 0)
        setError(null)
      } catch (_) {}
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchFromChain() }, [fetchFromChain])

  return (
    <section className="bg-[#0d1529] rounded-xl border border-blue-900/30 flex flex-col overflow-hidden flex-1 min-h-0">

      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-blue-900/30">
        <Link className="w-4 h-4 text-cyan-400" />
        <h2 className="font-semibold text-sm tracking-wide text-blue-200 uppercase">
          Blockchain Ledger
        </h2>
        {count !== null && (
          <span className="text-xs text-gray-500 ml-1">({count} total)</span>
        )}
        <button
          onClick={fetchFromChain}
          disabled={loading}
          className="ml-auto text-gray-400 hover:text-white transition-colors disabled:opacity-40"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="text-xs text-red-400 bg-red-900/20 px-3 py-1.5 border-b border-red-900/30">
          {error}
        </div>
      )}

      {/* Records */}
      <div className="flex-1 overflow-y-auto divide-y divide-blue-900/20">
        {!loading && records.length === 0 && (
          <div className="text-center text-xs text-gray-500 py-8">
            No records on chain yet.
          </div>
        )}

        {records.map(r => (
          <div key={r.record_id} className="px-3 py-2.5 hover:bg-white/5 transition-colors">
            {/* Row 1 */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-gray-500">#{r.record_id}</span>
              <span className="font-mono text-xs font-bold text-blue-300">{r.attacker_ip}</span>
              <span className="text-xs px-1.5 py-0.5 rounded bg-orange-900/50 text-orange-300">
                {r.attack_type}
              </span>
              <span className="ml-auto text-xs text-gray-500">
                {r.captured_at
                  ? new Date(r.captured_at * 1000).toLocaleString()
                  : ''}
              </span>
            </div>

            {/* Row 2 */}
            <div className="flex items-center gap-3 mt-1 text-xs text-gray-400">
              <span>OSINT: <span className="text-yellow-400 font-bold">{r.osint_score}</span></span>

              {/* IPFS link */}
              {r.ipfs_cid && (
                <a
                  href={ipfsGateway(r.ipfs_cid)}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-cyan-400 hover:underline"
                >
                  <ExternalLink className="w-3 h-3" />
                  IPFS
                </a>
              )}

              {/* Reporter (truncated) */}
              {r.reporter && r.reporter !== '0x0000000000000000000000000000000000000000' && (
                <span className="font-mono text-gray-600 hidden sm:inline">
                  {r.reporter.substring(0, 10)}…
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      {CONTRACT_ADDR && (
        <div className="px-3 py-2 border-t border-blue-900/30 text-xs text-gray-600">
          Contract:{' '}
          <a
            href={`https://sepolia.etherscan.io/address/${CONTRACT_ADDR}`}
            target="_blank"
            rel="noreferrer"
            className="text-cyan-700 hover:text-cyan-400 font-mono"
          >
            {CONTRACT_ADDR.substring(0, 14)}…
          </a>
          {' '}(Sepolia)
        </div>
      )}
    </section>
  )
}
