from pathlib import Path

p = Path('index.html')
s = p.read_text(encoding='utf-8')
MARK = 'VEA_REPARACION_BOLETIN_LAYOUT_20260915'
if MARK in s:
    print('REPARACION_YA_APLICADA')
    raise SystemExit(0)

# 1) El boletín no debe depender de un PDF estático que no forma parte de la aplicación.
old = """function abrirBoletinAvanzadoVea(){\n  const url='Hosp_Ventanilla_BOLETIN_SE_34_2026_PUNTO3_VEA_GRAFICOS_PRO.pdf';\n  const w=window.open(url,'_blank','noopener');\n  if(!w) alert('El navegador bloqueó la ventana del boletín. Habilita las ventanas emergentes para este módulo.');\n}"""
new = """function abrirBoletinAvanzadoVea(){\n  // Generación dinámica: usa exactamente el Año + S.E. elegidos en el selector.\n  if(typeof abrirAvisoBoletinSEVea === 'function'){\n    abrirAvisoBoletinSEVea();\n    return;\n  }\n  alert('El generador del Boletín VEA todavía no está disponible.');\n}"""
if old not in s:
    raise SystemExit('ERROR: no se encontró abrirBoletinAvanzadoVea')
s = s.replace(old, new, 1)

# 2) El selector debe abrir el boletín dinámico, no el archivo fijo.
old = "window.__veaBoletinSeleccion={anio,semana};\n  cerrarSelectorBoletinVea();actualizarTextoBoletinSEVea();abrirBoletinAvanzadoVea();"
new = "window.__veaBoletinSeleccion={anio,semana};\n  cerrarSelectorBoletinVea();actualizarTextoBoletinSEVea();abrirAvisoBoletinSEVea();"
if old not in s:
    raise SystemExit('ERROR: no se encontró flujo de generación del boletín')
s = s.replace(old, new, 1)

# 3) No eliminar ningún botón del menú al actualizar su etiqueta.
s = s.replace("  document.getElementById('btnBoletinProVea')?.remove();\n", "", 1)

# 4) Corrección de alineación del contenedor final, sin alterar motores ni datos.
css = '''<style id="vea-reparacion-boletin-layout-20260915">
/* VEA_REPARACION_BOLETIN_LAYOUT_20260915 — estabilización de presentación */
html,body{width:100%;max-width:100%;overflow-x:hidden}
#veaAppShell{width:100%;max-width:100%;min-width:0;box-sizing:border-box;overflow-x:clip}
#veaAppShell>main{box-sizing:border-box;width:100%;max-width:96rem!important;min-width:0;margin-left:auto!important;margin-right:auto!important}
#veaAppShell>main>:is(#contentDashboard,#contentCasos,#contentCanal,#contentTabla,#contentHospitalizados,#contentSoat,#contentVih,#contentTbc,#contentConfiguracion,#contentDatos){box-sizing:border-box;width:100%;max-width:none;min-width:0;margin-left:0;margin-right:0}
#contentConfiguracion{overflow-x:hidden}
#contentConfiguracion>*{box-sizing:border-box;max-width:100%}
@media(max-width:767px){
 #veaAppShell>main{width:100%!important;max-width:100%!important;padding-left:0!important;padding-right:0!important}
 #veaAppShell>main>:is(#contentDashboard,#contentCasos,#contentCanal,#contentTabla,#contentHospitalizados,#contentSoat,#contentVih,#contentTbc,#contentConfiguracion,#contentDatos){width:100%!important;max-width:100%!important}
}
</style>'''
if '</head>' not in s:
    raise SystemExit('ERROR: no se encontró cierre HEAD')
s = s.replace('</head>', css + '\n</head>', 1)

# 5) Validaciones que no confunden el HTML de la página con el HTML generado dentro del boletín.
if 'F6_20_MASTER_DINAMICO_CACHE_V2' not in s:
    raise SystemExit('ERROR: firma F6.20 ausente')
if 'abrirAvisoBoletinSEVea();' not in s:
    raise SystemExit('ERROR: generador dinámico del boletín ausente')
if 'VEA_REPARACION_BOLETIN_LAYOUT_20260915' not in s:
    raise SystemExit('ERROR: marcador de reparación ausente')

s = s.replace('</head>', f'<!-- {MARK} -->\n</head>', 1)
p.write_text(s, encoding='utf-8')
print('OK_REPARACION_BOLETIN_LAYOUT')
