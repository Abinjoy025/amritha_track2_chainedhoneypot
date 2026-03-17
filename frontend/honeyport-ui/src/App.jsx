import { useState, useEffect, useRef } from 'react'
import LiveFeed   from './components/LiveFeed.jsx'
import ShapPanel  from './components/ShapPanel.jsx'
import Web3Ledger from './components/Web3Ledger.jsx'
import StatsBar   from './components/StatsBar.jsx'
import { Shield, Wifi, WifiOff } from 'lucide-react'

const WS_URL = import.meta.env.VITE_WS_URL ?? `ws://${location.host}/ws/live`

export default function App() {
  const [events,    setEvents]    = useState([])   // live feed
  const [selected,  setSelected]  = useState(null) // clicked event for SHAP panel
  const [wsStatus,  setWsStatus]  = useState('connecting')
  const [stats,     setStats]     = useState(null)
  const wsRef = useRef(null)

  // ── WebSocket connection ─────────────────────────────────────────────────
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen  = () => setWsStatus('connected')
      ws.onclose = () => {
        setWsStatus('disconnected')
        setTimeout(connect, 3000)   // auto-reconnect
      }
      ws.onerror = () => setWsStatus('error')

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          setEvents(prev => [data, ...prev].slice(0, 200))  // keep last 200
          if (data.type === 'session_complete') {
            fetchStats()
          }
        } catch (_) {}
      }
    }
    connect()
    return () => wsRef.current?.close()
  }, [])

  // ── Initial stats load ───────────────────────────────────────────────────
  const fetchStats = async () => {
    try {
      const r = await fetch('/api/stats')
      setStats(await r.json())
    } catch (_) {}
  }

  // ── Load historical attacks from blockchain/mock on startup ──────────────
  const fetchHistory = async () => {
    try {
      const r = await fetch('/api/attacks/latest?n=50')
      const data = await r.json()
      const normalized = (data.records || []).map(rec => ({
        type:        'session_complete',
        ip:          rec.attacker_ip,
        attack_type: rec.attack_type,
        osint_score: rec.osint_score,
        ipfs_cid:    rec.ipfs_cid,
        is_attack:   rec.attack_type !== 'Benign' && rec.attack_type !== 'Unknown',
        rf_verdict:  rec.attack_type === 'Benign' ? 'Benign' : 'Malicious',
        timestamp:   rec.captured_at
          ? new Date(rec.captured_at * 1000).toISOString()
          : null,
        record_id:   rec.record_id,
        _historical: true,
      }))
      setEvents(normalized)
    } catch (_) {}
  }

  useEffect(() => { fetchStats(); fetchHistory() }, [])

  // ── Status badge ─────────────────────────────────────────────────────────
  const statusColor = {
    connected:    'text-emerald-400',
    disconnected: 'text-red-400',
    connecting:   'text-yellow-400',
    error:        'text-red-500',
  }[wsStatus]

  return (
    <div className="min-h-screen bg-[#060b18] flex flex-col">

      {/* ── Header ── */}
      <header className="border-b border-blue-900/40 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-blue-400" />
          <span className="text-lg font-bold tracking-widest text-blue-300 uppercase">
            Honeyport  Command Center
          </span>
        </div>
        <div className={`flex items-center gap-1.5 text-sm ${statusColor}`}>
          {wsStatus === 'connected'
            ? <Wifi className="w-4 h-4" />
            : <WifiOff className="w-4 h-4" />}
          <span className="capitalize">{wsStatus}</span>
        </div>
      </header>

      {/* ── Stats bar ── */}
      {stats && <StatsBar stats={stats} />}

      {/* ── Main grid ── */}
      <main className="flex-1 grid grid-cols-1 xl:grid-cols-3 gap-4 p-4 overflow-hidden">

        {/* Left – Live Feed (2/3 width on xl) */}
        <div className="xl:col-span-2 flex flex-col gap-4 min-h-0">
          <LiveFeed events={events} onSelect={setSelected} />
        </div>

        {/* Right – SHAP Panel + Web3 Ledger */}
        <div className="flex flex-col gap-4 min-h-0">
          <ShapPanel event={selected} />
          <Web3Ledger />
        </div>

      </main>
    </div>
  )
}
