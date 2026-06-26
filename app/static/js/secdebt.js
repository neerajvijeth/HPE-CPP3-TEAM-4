window.__DEBT_HISTORY__ = {
      labels: [{% for r in history %}"{{ r.run_at.strftime('%m/%d %H:%M') }}"{% if not loop.last %},{% endif %}{% endfor %}],
      scores: [{% for r in history %}{{ r.total_debt_score }}{% if not loop.last %},{% endif %}{% endfor %}]
    };