CREATE DATABASE UgaldesCakeShop;
USE `UgaldesCakeShop`;
--
-- Tabla para los administradores
--
CREATE TABLE `administradores` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(50) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `fecha_creacion` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `username_UNIQUE` (`username` ASC)
) ENGINE=InnoDB;

-- Insertar un administrador por defecto. Contraseña: 'admin123'
INSERT INTO `administradores` (`username`, `password`) VALUES ('admin', '$2y$10$g.gB5k5.W8v569aR/1dYguB2B5.wL/3s.JC.j82f34vYgE.5nKz2S');
INSERT INTO `administradores` (`username`, `password`) VALUES ('caro', 'valecaro15');

DELETE FROM `administradores` WHERE `username` = 'admin';
--
-- Tabla para los clientes
--
CREATE TABLE `clientes` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `nombre` VARCHAR(100) NOT NULL,
  `email` VARCHAR(100) NULL,
  `telefono` VARCHAR(20) NULL,
  `fecha_registro` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `email_UNIQUE` (`email` ASC)
) ENGINE=InnoDB;

--
-- Tabla para los catálogo de pasteles y postres
--
CREATE TABLE `tipos_invitacion` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `nombre` VARCHAR(50) NOT NULL,
  `precio_base` DECIMAL(10,2) NOT NULL,
  `caracteristicas` TEXT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

ALTER TABLE `tipos_invitacion` 
ADD COLUMN `url_imagen` VARCHAR(255) NULL DEFAULT NULL AFTER `caracteristicas`;
--
-- Tabla para los servicios adicionales
--
CREATE TABLE `servicios_adicionales` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `nombre` VARCHAR(100) NOT NULL,
  `precio` DECIMAL(10,2) NOT NULL,
  `descripcion` TEXT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

CREATE TABLE `descuentos` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `nombre` VARCHAR(180) NOT NULL,
  `tipo` ENUM('porcentaje','fijo') NOT NULL DEFAULT 'porcentaje',
  `valor` DECIMAL(12,2) NOT NULL,
  `descripcion` TEXT NULL,
  `activo` TINYINT(1) NOT NULL DEFAULT 1,
  `fecha_registro` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `descuentos_nombre_unique` (`nombre`)
) ENGINE=InnoDB;

CREATE TABLE `configuracion_portal` (
  `clave` VARCHAR(80) NOT NULL,
  `valor` TEXT NOT NULL,
  `fecha_actualizacion` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`clave`)
) ENGINE=InnoDB;

INSERT INTO `configuracion_portal` (`clave`,`valor`) VALUES
('password_administrador','$2a$12$qiwkeemhfkJZ0Th33UqhN.enBA/JkbMsTOK5MNF7Hqz7CA2mMAeCa');

--
-- Tabla para los pedidos
--
CREATE TABLE `pedidos` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `cliente_id` INT UNSIGNED NOT NULL,
  `tipo_id` INT UNSIGNED NOT NULL,
  `nombre_evento` VARCHAR(150) NULL,
  `fecha_evento` DATE NULL,
  `hora_evento` TIME NULL,
  `precio_final` DECIMAL(10,2) NOT NULL,
  `notas` TEXT NULL,
  `descuento_id` INT UNSIGNED NULL,
  `descuento_nombre_snapshot` VARCHAR(180) NULL,
  `descuento_tipo_snapshot` VARCHAR(20) NULL,
  `descuento_valor_snapshot` DECIMAL(12,2) NULL,
  `descuento_monto_snapshot` DECIMAL(12,2) NOT NULL DEFAULT 0,
  `fecha_creacion` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `fk_pedidos_cliente_idx` (`cliente_id` ASC),
  INDEX `fk_pedidos_tipo_idx` (`tipo_id` ASC),
  CONSTRAINT `fk_pedidos_cliente`
    FOREIGN KEY (`cliente_id`)
    REFERENCES `clientes` (`id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_pedidos_tipo`
    FOREIGN KEY (`tipo_id`)
    REFERENCES `tipos_invitacion` (`id`)
    ON DELETE RESTRICT
    ON UPDATE NO ACTION
) ENGINE=InnoDB;

ALTER TABLE `pedidos` 
ADD COLUMN `entregado` TINYINT(1) NOT NULL DEFAULT 0 AFTER `precio_final`,
ADD COLUMN `fecha_entrega_real` TIMESTAMP NULL DEFAULT NULL AFTER `entregado`;

--
-- Tabla intermedia para conectar pedidos con servicios
--
CREATE TABLE `pedido_servicios` (
  `pedido_id` INT UNSIGNED NOT NULL,
  `servicio_id` INT UNSIGNED NOT NULL,
  `servicio_descripcion_snapshot` TEXT NULL,
  PRIMARY KEY (`pedido_id`, `servicio_id`),
  INDEX `fk_ps_servicio_idx` (`servicio_id` ASC),
  CONSTRAINT `fk_ps_pedido`
    FOREIGN KEY (`pedido_id`)
    REFERENCES `pedidos` (`id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ps_servicio`
    FOREIGN KEY (`servicio_id`)
    REFERENCES `servicios_adicionales` (`id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION
) ENGINE=InnoDB;

--
-- Tabla para los pagos de cada pedido
--
CREATE TABLE `pagos` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `pedido_id` INT UNSIGNED NOT NULL,
  `monto` DECIMAL(10,2) NOT NULL,
  `metodo` VARCHAR(50) NULL,
  `fecha_pago` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX `fk_pagos_pedido_idx` (`pedido_id` ASC),
  CONSTRAINT `fk_pagos_pedido`
    FOREIGN KEY (`pedido_id`)
    REFERENCES `pedidos` (`id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION
) ENGINE=InnoDB;

--
-- Tabla para los bocetos
--
CREATE TABLE `bocetos` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `nombre_archivo` VARCHAR(255) NOT NULL,
  `fecha_subida` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

--
-- Tabla para las notificaciones
--
CREATE TABLE `notificaciones` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `mensaje` VARCHAR(255) NOT NULL,
  `link` VARCHAR(255) NULL,
  `leida` TINYINT(1) NOT NULL DEFAULT 0,
  `fecha_creacion` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

ALTER TABLE `notificaciones` 
ADD COLUMN `fecha_leida` TIMESTAMP NULL DEFAULT NULL AFTER `leida`;




