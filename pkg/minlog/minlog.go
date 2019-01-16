package minlog

import (
	"strings"

	"github.com/golang/glog"
	"github.com/minio/minio-go"
)

type MinLog struct {
	log    string
	bucket string
	file   string
	mc     *minio.Client
}

func New(mc *minio.Client, bucket, file string) *MinLog {
	return &MinLog{
		bucket: bucket,
		file:   file,
		mc:     mc,
	}
}

func (m *MinLog) Write(data []byte) (int, error) {
	m.log = m.log + string(data)
	if _, err := m.mc.PutObject(m.bucket, m.file, strings.NewReader(m.log), int64(len(m.log)), minio.PutObjectOptions{
		ContentType: "encoding/text",
	}); err != nil {
		glog.Errorf("error pushing log file:%s to minio: %v", m.file, err)
		return -1, err
	}
	glog.V(5).Infof("%s", string(data))
	return len(data), nil
}

func (m *MinLog) Read(p []byte) (int, error) {
	return strings.NewReader(m.log).Read(p)
}
