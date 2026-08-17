-- Notas, descripciones historicas, descuentos y gastos anuales.
ALTER TABLE servicios_adicionales
  ADD COLUMN IF NOT EXISTS descripcion TEXT NULL AFTER precio;

ALTER TABLE pedidos
  ADD COLUMN IF NOT EXISTS notas TEXT NULL,
  ADD COLUMN IF NOT EXISTS descuento_id INT UNSIGNED NULL,
  ADD COLUMN IF NOT EXISTS descuento_nombre_snapshot VARCHAR(180) NULL,
  ADD COLUMN IF NOT EXISTS descuento_tipo_snapshot VARCHAR(20) NULL,
  ADD COLUMN IF NOT EXISTS descuento_valor_snapshot DECIMAL(12,2) NULL,
  ADD COLUMN IF NOT EXISTS descuento_monto_snapshot DECIMAL(12,2) NOT NULL DEFAULT 0;

ALTER TABLE pedido_servicios
  ADD COLUMN IF NOT EXISTS servicio_descripcion_snapshot TEXT NULL;

ALTER TABLE gastos
  MODIFY frecuencia ENUM('unica','mensual','anual') NOT NULL DEFAULT 'unica';

CREATE TABLE IF NOT EXISTS descuentos (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  nombre VARCHAR(180) NOT NULL,
  tipo ENUM('porcentaje','fijo') NOT NULL DEFAULT 'porcentaje',
  valor DECIMAL(12,2) NOT NULL,
  descripcion TEXT NULL,
  activo TINYINT(1) NOT NULL DEFAULT 1,
  fecha_registro TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY descuentos_nombre_unique (nombre)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS configuracion_portal (
  clave VARCHAR(80) NOT NULL PRIMARY KEY,
  valor TEXT NOT NULL,
  fecha_actualizacion TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT IGNORE INTO configuracion_portal(clave,valor)
VALUES ('password_administrador','$2a$12$qiwkeemhfkJZ0Th33UqhN.enBA/JkbMsTOK5MNF7Hqz7CA2mMAeCa');
