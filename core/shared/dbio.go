/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-21 11:35:08
 * @LastEditTime: 2025-11-25 20:06:05
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/shared/dbio.go
 */

package shared

import (
	"context"
	"database/sql"
	"errors"
)

// Pre-defined SQL queries
const (
	QueryGetConf string = "SELECT VALUE FROM `CONFIG` WHERE `KEY` = ? LIMIT 1;"
	QueryGetMemo string = "SELECT VALUE FROM `MEMO` WHERE `KEY` = ? LIMIT 1;"
)

// Pre-defined errors
var (
	ErrInvalidDBConn error = errors.New("invalid DB connection")
	ErrInvalidDBTx   error = errors.New("invalid DB transaction")
)

// Get config value from db connection specified
func GetConfVal[T any](ctx context.Context, conn *sql.DB, key string, to *T) error {
	if conn == nil {
		return ErrInvalidDBConn
	}
	row := conn.QueryRowContext(ctx, QueryGetConf, key)
	err := row.Scan(to)
	return err
}

// Get conf value from db in a transaction
func GetConfValTx[T any](ctx context.Context, tx *sql.Tx, key string, to *T) error {
	if tx == nil {
		return ErrInvalidDBTx
	}
	row := tx.QueryRowContext(ctx, QueryGetConf, key)
	err := row.Scan(to)
	return err
}

// Get memo value from db connection specified
func GetMemoVal[T any](ctx context.Context, conn *sql.DB, key string, to *T) error {
	if conn == nil {
		return ErrInvalidDBConn
	}
	row := conn.QueryRowContext(ctx, QueryGetMemo, key)
	err := row.Scan(to)
	return err
}

// Get memo value from db in a transaction
func GetMemoValTx[T any](ctx context.Context, tx *sql.Tx, key string, to *T) error {
	if tx == nil {
		return ErrInvalidDBTx
	}
	row := tx.QueryRowContext(ctx, QueryGetMemo, key)
	err := row.Scan(to)
	return err
}
