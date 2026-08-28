ALTER TABLE pedidos
  ADD COLUMN cancelado TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN fecha_cancelacion DATETIME NULL,
  ADD COLUMN motivo_cancelacion TEXT NULL,
  ADD COLUMN resolucion_anticipo VARCHAR(30) NULL,
  ADD COLUMN monto_anticipo_cancelacion DECIMAL(12,2) NOT NULL DEFAULT 0;
