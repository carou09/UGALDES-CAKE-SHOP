ALTER TABLE pedidos
  ADD COLUMN hora_entrega TIME NULL AFTER fecha_entrega,
  ADD COLUMN diseno_imagen LONGBLOB NULL,
  ADD COLUMN diseno_imagen_mime VARCHAR(100) NULL,
  ADD COLUMN diseno_imagen_nombre VARCHAR(255) NULL;

UPDATE pedidos
SET hora_entrega=MAKETIME(GREATEST(HOUR(hora_evento)-2,0),MINUTE(hora_evento),0)
WHERE hora_entrega IS NULL AND hora_evento IS NOT NULL;
