import { formatDistanceToNow } from 'date-fns'
import { AlertTriangle, Info, Globe, Zap } from 'lucide-react'

const SEVERITY_COLORS = {
  BruteForce:   'border-orange-500 bg-orange-500/10',
  DDoS:         'border-red-500   bg-red-500/10',
  DoS:          'border-red-400   bg-red-400/10',
  PortScan:     'border-yellow-500 bg-yellow-500/10',
  WebAttack:    'border-purple-500 bg-purple-500/10',
  Bot:          'border-pink-500  bg-pink-500/10',
  Infiltration: 'border-red-600   bg-red-600/10',
  Heartbleed:   'border-red-700   bg-red-700/10',
  Benign:       'border-green-500 bg-green-500/10',
  Unknown:      'border-gray-500  bg-gray-500/10',
}

function typeColor(type) {
  return SEVERITY_COLORS[type] ?? SEVERITY_COLORS.Unknown
}

function osintBadge(score) {
  if (score >= 75) return 'bg-red-600 text-white'
  if (score >= 40) return 'bg-orange-500 text-white'
  if (score >= 10) return 'bg-yellow-500 text-black'
  return 'bg-gray-600 text-gray-200'
}

export default function LiveFeed({ events, onSelect }) {
  return (
    <section className="bg-[#0d1529] rounded-xl border border-blue-900/30 flex flex-col overflow-hidden h-full">

      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-blue-900/30">
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
        </span>
        <h2 className="font-semibold text-sm tracking-wide text-blue-200 uppercase">
          Live Attack Feed
        </h2>
        <span className="ml-auto text-xs text-gray-500">{events.length} events</span>
      </div>

      {/* Event list */}
      <div className="flex-1 overflow-y-auto divide-y divide-blue-900/20">
        {events.length === 0 && (
          <div className="flex flex-col items-center justify-center h-40 gap-2 text-gray-600">
            <Info className="w-8 h-8" />
            <span className="text-sm">Waiting for attackers…</span>
          </div>
        )}

        {events.map((ev, idx) => (
          <button
            key={idx}
            onClick={() => onSelect(ev)}
            className={`w-full text-left px-4 py-3 hover:bg-white/5 transition-colors
                        border-l-2 ${typeColor(ev.attack_type ?? '')} flex items-start gap-3`}
          >
            {/* Icon */}
            <div className="mt-0.5 shrink-0">
              {ev.type === 'session_complete'
                ? <AlertTriangle className="w-4 h-4 text-orange-400" />
                : <Globe className="w-4 h-4 text-blue-400" />}
            </div>

            {/* Main content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                {/* IP */}
                <span className="font-mono text-sm font-bold text-blue-300">
                  {ev.ip}
                </span>

                {/* Attack type badge */}
                {ev.attack_type && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-200">
                    {ev.attack_type}
                  </span>
                )}

                {/* Malicious / Benign verdict */}
                {ev.type === 'session_complete' && ev.rf_verdict && (
                  <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${
                    ev.rf_verdict === 'Malicious'
                      ? 'bg-red-900/70 text-red-300'
                      : 'bg-green-900/70 text-green-300'
                  }`}>
                    {ev.rf_verdict}
                  </span>
                )}

                {/* OSINT score */}
                {ev.osint_score !== undefined && (
                  <span className={`text-xs px-1.5 py-0.5 rounded font-bold ${osintBadge(ev.osint_score)}`}>
                    OSINT {ev.osint_score}
                  </span>
                )}

                {/* SOAR fired */}
                {ev.soar_fired && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-red-900/70 text-red-300 flex items-center gap-1">
                    <Zap className="w-3 h-3" /> SOAR
                  </span>
                )}

                {/* Timestamp */}
                <span className="ml-auto text-xs text-gray-500 shrink-0">
                  {ev.timestamp
                    ? formatDistanceToNow(new Date(ev.timestamp), { addSuffix: true })
                    : ''}
                </span>
              </div>

              {/* Sub-detail */}
              <div className="flex flex-wrap gap-3 mt-0.5 text-xs text-gray-400">
                {ev.country    && <span>🌍 {ev.country}</span>}
                {ev.isp        && <span>🏢 {ev.isp}</span>}
                {ev.osint_label && <span className="text-yellow-400">{ev.osint_label}</span>}
                {ev.trigger    && <span className="text-gray-500">trigger: {ev.trigger}</span>}
              </div>

              {/* Shodan tags */}
              {ev.shodan_tags?.length > 0 && (
                <div className="flex gap-1 mt-1 flex-wrap">
                  {ev.shodan_tags.map(t => (
                    <span key={t} className="text-xs px-1 py-0.5 rounded bg-purple-900/50 text-purple-300">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </button>
        ))}
      </div>
    </section>
  )
}
