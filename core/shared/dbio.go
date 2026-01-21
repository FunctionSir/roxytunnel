/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-21 11:35:08
 * @LastEditTime: 2025-11-26 11:39:36
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

const (
	QuerySetMemo string = "UPDATE `MEMO` SET `VALUE` = ? WHERE `KEY` = ?"
)

// Pre-defined errors
var (
	ErrInvalidDBConn          error = errors.New("invalid DB connection")
	ErrInvalidDBTx            error = errors.New("invalid DB transaction")
	ErrUnexpectedRowsAffected error = errors.New("unexpected rows affected")
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
	if err != nil {
		_ = tx.Rollback()
	}
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
	if err != nil {
		_ = tx.Rollback()
	}
	return err
}

func SetMemoValTx[T any](ctx context.Context, tx *sql.Tx, key string, val T) error {
	if tx == nil {
		return ErrInvalidDBTx
	}
	res, err := tx.ExecContext(ctx, QuerySetMemo, val, key)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		_ = tx.Rollback()
		return ErrUnexpectedRowsAffected
	}
	return nil
}
