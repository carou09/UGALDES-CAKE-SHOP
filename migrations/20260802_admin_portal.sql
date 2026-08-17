ALTER TABLE pedidos
  ADD COLUMN fecha_entrega DATE NULL AFTER fecha_evento;

UPDATE pedidos
SET fecha_entrega = fecha_evento
WHERE fecha_entrega IS NULL AND fecha_evento IS NOT NULL;

ALTER TABLE notificaciones
  ADD COLUMN pedido_id INT UNSIGNED NULL AFTER id,
  ADD COLUMN tipo VARCHAR(40) NULL AFTER pedido_id;

CREATE UNIQUE INDEX uq_notificaciones_pedido_tipo
  ON notificaciones(pedido_id, tipo);
