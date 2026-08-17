-- Referencia de la migración aplicada automáticamente por api/index.js.
ALTER TABLE pedidos
  ADD COLUMN fecha_liquidacion DATE NULL,
  ADD COLUMN formulario_completado TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN fecha_formulario_completado DATETIME NULL,
  ADD COLUMN invitacion_entregada TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN fecha_invitacion_entregada DATETIME NULL,
  ADD COLUMN fecha_liquidado DATETIME NULL;

UPDATE pedidos
SET fecha_liquidacion = DATE_ADD(fecha_evento, INTERVAL 1 DAY)
WHERE fecha_liquidacion IS NULL AND fecha_evento IS NOT NULL;
