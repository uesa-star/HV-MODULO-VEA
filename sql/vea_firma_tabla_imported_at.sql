-- Actualiza la firma remota usada por el módulo VEA para invalidar cachés del navegador.
-- Incluye _imported_at para detectar reimportaciones aunque se mantenga el mismo
-- número de filas y la misma semana epidemiológica máxima.

CREATE OR REPLACE FUNCTION public.vea_firma_tabla(p_tabla text)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path TO ''
AS $function$
DECLARE
  v_count bigint;
  v_ano text;
  v_semana integer;
  v_imported_at timestamptz;
  v_anio_actual text := to_char(current_date, 'YYYY');
BEGIN
  IF p_tabla IS NULL OR p_tabla NOT IN ('edas', 'iras', 'febriles', 'individual') THEN
    RAISE EXCEPTION 'Tabla no permitida para firma VEA: %', p_tabla
      USING ERRCODE = '22023';
  END IF;

  EXECUTE format(
    'SELECT
       count(*) FILTER (WHERE ano = $1),
       coalesce(max(ano) FILTER (WHERE ano = $1), ''''),
       coalesce(max(CASE
         WHEN ano = $1 AND semana ~ ''^[0-9]{1,2}$'' THEN semana::integer
         ELSE NULL
       END), 0),
       max(_imported_at)
     FROM public.%I',
    p_tabla
  )
  INTO v_count, v_ano, v_semana, v_imported_at
  USING v_anio_actual;

  RETURN v_count::text || ':' ||
         v_ano || ':' ||
         v_semana::text || ':' ||
         coalesce(v_imported_at::text, '');
END;
$function$;

COMMENT ON FUNCTION public.vea_firma_tabla(text) IS
'Firma de actualización VEA: total del año vigente, año, semana epidemiológica máxima y última importación. Detecta cambios del Excel aunque la cantidad de filas y la semana máxima no varíen.';