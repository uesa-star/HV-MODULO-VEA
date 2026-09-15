from pathlib import Path
import hashlib

p = Path('index.html')
s = p.read_text(encoding='utf-8')

if 'F6_20_MASTER_DINAMICO_CACHE_V2' not in s:
    raise SystemExit('ERROR: INDEX no corresponde a F6.20')

# 1. Contraste de iconos KPI: solo clase visual, sin tocar estructura.
old_icon = 'w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/20 flex items-center justify-center shrink-0'
new_icon = old_icon + ' vea-kpi-icon-shell'
s = s.replace(old_icon, new_icon)

# 2. Valores sobre barras: contraste por tema y posición arriba de la barra.
s = s.replace("ctx.fillStyle = '#e2e8f0';", "ctx.fillStyle = document.documentElement.dataset.veaTheme === 'light' ? '#0f172a' : '#f8fafc';", 1)
s = s.replace(
    "ctx.fillText(valor.toLocaleString('es-PE'), pos.x, pos.y - 5);",
    "const yEtiqueta = Math.max(12, pos.y - 10);\n                            ctx.fillText(valor.toLocaleString('es-PE'), pos.x, yEtiqueta);",
    1,
)

# 3. CSS visual aprobado. No modifica datos, filtros, listeners ni cálculos.
STYLE_MARK = 'VEA_VISUAL_FINAL_APROBADO_20260915'
if STYLE_MARK not in s:
    css = r'''<style id="vea-visual-final-aprobado-20260915">
/* VEA_VISUAL_FINAL_APROBADO_20260915 — solo presentación */
.vea-kpi-icon-shell{
  background:linear-gradient(180deg,rgba(18,73,148,.28) 0%,rgba(10,41,91,.42) 100%)!important;
  border:1px solid rgba(96,165,250,.40)!important;color:#67d7ff!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06),0 6px 16px rgba(2,8,23,.18)!important;
}
.vea-kpi-icon-shell svg{color:inherit!important}
html[data-vea-theme="light"] .vea-kpi-icon-shell{
  background:linear-gradient(180deg,#e0f0ff 0%,#cfe5ff 100%)!important;
  border:1px solid #8cb6e8!important;color:#0b4c97!important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.75),0 4px 10px rgba(37,99,235,.10)!important;
}
/* Ocultar metadatos superiores duplicados, salvo AÑO de edades */
:is(#txtSemanalGraficoAño,#txtMesualGraficoAño,#ciGraficoMensualAnios,#ciGraficoSemanalAnios,#ciGraficoDiagnosticoAnios,#txtHospGrafAnualAnios,#txtHospGrafSemanalAnios,#txtHospGrafMensualAnios,#soatGraficoMensualAnios){display:none!important}
div:has(> :is(#txtSemanalGraficoAño,#txtMesualGraficoAño,#ciGraficoMensualAnios,#ciGraficoSemanalAnios,#ciGraficoDiagnosticoAnios,#txtHospGrafAnualAnios,#txtHospGrafSemanalAnios,#txtHospGrafMensualAnios,#soatGraficoMensualAnios)){display:none!important}
/* Año activo visible en gráficos de edades */
#txtVeaEdadAnioActivo,#ciGraficoEdadAnio,#txtHospGrafEdadesAnios{display:inline!important;font-weight:900!important}
div:has(> :is(#txtVeaEdadAnioActivo,#ciGraficoEdadAnio,#txtHospGrafEdadesAnios)){display:block!important}
html[data-vea-theme="light"] :is(#txtVeaEdadAnioActivo,#ciGraficoEdadAnio,#txtHospGrafEdadesAnios){color:#0f172a!important}
html[data-vea-theme="dark"] :is(#txtVeaEdadAnioActivo,#ciGraficoEdadAnio,#txtHospGrafEdadesAnios){color:#f8fafc!important}
/* Tarjetas de gráficos: mismo layout, contraste consistente */
html[data-vea-theme="dark"] main :is(#contentDashboard,#contentHospitalizados,#contentCasos,#contentSoat,#contentDatos,#contentVih,#contentTbc) :is(div,article).rounded-2xl:has(canvas){
  background:linear-gradient(180deg,#071b33 0%,#061629 100%)!important;border-color:#1f5b91!important;border-top:4px solid #2f6df6!important;
}
html[data-vea-theme="light"] main :is(#contentDashboard,#contentHospitalizados,#contentCasos,#contentSoat,#contentDatos,#contentVih,#contentTbc) :is(div,article).rounded-2xl:has(canvas){
  background:#fff!important;border-color:#cbd8e6!important;border-top:4px solid #2f6df6!important;
}
html[data-vea-theme="dark"] main :is(#contentDashboard,#contentHospitalizados,#contentCasos,#contentSoat,#contentDatos,#contentVih,#contentTbc) :is(div,article).rounded-2xl:has(canvas) :is(h3,h4){color:#f8fafc!important}
html[data-vea-theme="light"] main :is(#contentDashboard,#contentHospitalizados,#contentCasos,#contentSoat,#contentDatos,#contentVih,#contentTbc) :is(div,article).rounded-2xl:has(canvas) :is(h3,h4){color:#0f172a!important}
</style>'''
    s = s.replace('</head>', css + '\n</head>', 1)

# 4. Plugin seguro para mantener el contraste de leyendas/ejes al recrear gráficos.
PLUGIN_MARK = 'VEA_PLUGIN_CONTRASTE_GRAFICOS_20260915'
if PLUGIN_MARK not in s:
    plugin = r'''
        // VEA_PLUGIN_CONTRASTE_GRAFICOS_20260915 — presentación únicamente.
        const VEA_PLUGIN_CONTRASTE_GRAFICOS_20260915 = {
            id: 'veaContrasteGraficos20260915',
            beforeUpdate(chart) {
                const claro = document.documentElement.dataset.veaTheme === 'light';
                const colorLeyenda = claro ? '#334155' : '#e2e8f0';
                const colorEje = claro ? '#475569' : '#cbd5e1';
                const colorGrid = claro ? 'rgba(71,85,105,.16)' : 'rgba(148,163,184,.16)';
                const op = chart.options || {};
                if (op.plugins?.legend?.labels) {
                    op.plugins.legend.labels.color = colorLeyenda;
                    op.plugins.legend.labels.font = { ...(op.plugins.legend.labels.font || {}), weight: '700' };
                }
                Object.values(op.scales || {}).forEach(escala => {
                    if (!escala) return;
                    if (escala.ticks) {
                        escala.ticks.color = colorEje;
                        escala.ticks.font = { ...(escala.ticks.font || {}), weight: '600' };
                    }
                    if (escala.grid && escala.grid.display !== false) escala.grid.color = colorGrid;
                });
            }
        };
        if (typeof Chart !== 'undefined' && Chart.register) Chart.register(VEA_PLUGIN_CONTRASTE_GRAFICOS_20260915);
'''
    anchor = "if (typeof Chart !== 'undefined' && Chart.register) Chart.register(VEA_PLUGIN_VALORES_BARRAS_F503);"
    if anchor not in s:
        raise SystemExit('ERROR: no se encontró anchor Chart.js')
    s = s.replace(anchor, anchor + plugin, 1)

# 5. Indicador superior solicitado para el corte aprobado S.E.36.
# Se fuerza solo la presentación del texto; no se altera la carga de datos.
STATUS_MARK = 'VEA_STATUS_SE36_APROBADO_20260915'
if STATUS_MARK not in s:
    status = r'''
<script id="vea-status-se36-aprobado-20260915">
// VEA_STATUS_SE36_APROBADO_20260915
(function(){
  const aplicar=()=>{
    const el=document.getElementById('estadoCargaVea') || document.getElementById('veaEstadoCarga') || document.querySelector('[data-vea-estado-carga]');
    if(el) el.textContent='Última sincronización: lunes 14.Sep.2026 - 01:00 p. m. · S.E. 36';
  };
  document.addEventListener('DOMContentLoaded',aplicar);
  window.addEventListener('load',()=>{aplicar();setTimeout(aplicar,600);setTimeout(aplicar,1800)});
})();
</script>'''
    s = s.replace('</body>', status + '\n</body>', 1)

p.write_text(s, encoding='utf-8')
print('SHA256', hashlib.sha256(p.read_bytes()).hexdigest())
print('ICONOS', s.count('vea-kpi-icon-shell'))
print('OK')
