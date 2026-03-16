import { Activity, ShieldAlert, Database, BarChart2 } from 'lucide-react'

export default function StatsBar({ stats }) {
  if (!stats) return null

  const topType = Object.entries(stats.by_attack_type ?? {})
    .sort((a, b) => b[1] - a[1])[0]

  return (
    <div className="flex flex-wrap gap-3 px-4 py-2 border-b border-blue-900/30 bg-[#0a0f1e]">

      <StatCard
        icon={<ShieldAlert className="w-4 h-4 text-red-400" />}
        label="Total Attacks"
        value={stats.total_attacks ?? 0}
        color="text-red-300"
      />

      <StatCard
        icon={<Activity className="w-4 h-4 text-orange-400" />}
        label="Top Attack Type"
        value={topType ? `${topType[0]} (${topType[1]})` : '—'}
        color="text-orange-300"
      />

      <StatCard
        icon={<BarChart2 className="w-4 h-4 text-yellow-400" />}
        label="Avg OSINT Score"
        value={`${stats.avg_osint_score ?? 0} / 100`}
        color="text-yellow-300"
      />

      <StatCard
        icon={<Database className="w-4 h-4 text-cyan-400" />}
        label="Last Updated"
        value={stats.timestamp
          ? new Date(stats.timestamp).toLocaleTimeString()
          : '—'}
        color="text-cyan-300"
      />

    </div>
  )
}

function StatCard({ icon, label, value, color }) {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-900/20 border border-blue-900/30">
      {icon}
      <div>
        <div className="text-xs text-gray-500">{label}</div>
        <div className={`text-sm font-bold ${color}`}>{value}</div>
      </div>
    </div>
  )
}
