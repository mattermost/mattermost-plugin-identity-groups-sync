// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/mattermost/mattermost-plugin-identity-groups-sync/server/groups (interfaces: Client)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gocloak "github.com/Nerzal/gocloak/v13"
	gomock "github.com/golang/mock/gomock"
	saml2 "github.com/mattermost/gosaml2"
	groups "github.com/mattermost/mattermost-plugin-identity-groups-sync/server/groups"
	model "github.com/mattermost/mattermost/server/public/model"
	plugin "github.com/mattermost/mattermost/server/public/plugin"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// Authenticate mocks base method.
func (m *MockClient) Authenticate(arg0 context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authenticate", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Authenticate indicates an expected call of Authenticate.
func (mr *MockClientMockRecorder) Authenticate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authenticate", reflect.TypeOf((*MockClient)(nil).Authenticate), arg0)
}

// GetGroup mocks base method.
func (m *MockClient) GetGroup(arg0 context.Context, arg1 string) (*model.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroup", arg0, arg1)
	ret0, _ := ret[0].(*model.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroup indicates an expected call of GetGroup.
func (mr *MockClientMockRecorder) GetGroup(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroup", reflect.TypeOf((*MockClient)(nil).GetGroup), arg0, arg1)
}

// GetGroupMembers mocks base method.
func (m *MockClient) GetGroupMembers(arg0 context.Context, arg1 string) ([]*gocloak.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupMembers", arg0, arg1)
	ret0, _ := ret[0].([]*gocloak.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupMembers indicates an expected call of GetGroupMembers.
func (mr *MockClientMockRecorder) GetGroupMembers(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupMembers", reflect.TypeOf((*MockClient)(nil).GetGroupMembers), arg0, arg1)
}

// GetGroupSource mocks base method.
func (m *MockClient) GetGroupSource() model.GroupSource {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupSource")
	ret0, _ := ret[0].(model.GroupSource)
	return ret0
}

// GetGroupSource indicates an expected call of GetGroupSource.
func (mr *MockClientMockRecorder) GetGroupSource() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupSource", reflect.TypeOf((*MockClient)(nil).GetGroupSource))
}

// GetGroups mocks base method.
func (m *MockClient) GetGroups(arg0 context.Context, arg1 groups.Query) ([]*model.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroups", arg0, arg1)
	ret0, _ := ret[0].([]*model.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroups indicates an expected call of GetGroups.
func (mr *MockClientMockRecorder) GetGroups(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroups", reflect.TypeOf((*MockClient)(nil).GetGroups), arg0, arg1)
}

// GetGroupsCount mocks base method.
func (m *MockClient) GetGroupsCount(arg0 context.Context, arg1 string) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupsCount", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupsCount indicates an expected call of GetGroupsCount.
func (mr *MockClientMockRecorder) GetGroupsCount(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupsCount", reflect.TypeOf((*MockClient)(nil).GetGroupsCount), arg0, arg1)
}

// HandleSAMLLogin mocks base method.
func (m *MockClient) HandleSAMLLogin(arg0 *plugin.Context, arg1 *model.User, arg2 *saml2.AssertionInfo, arg3 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleSAMLLogin", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleSAMLLogin indicates an expected call of HandleSAMLLogin.
func (mr *MockClientMockRecorder) HandleSAMLLogin(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleSAMLLogin", reflect.TypeOf((*MockClient)(nil).HandleSAMLLogin), arg0, arg1, arg2, arg3)
}

// SyncGroupMap mocks base method.
func (m *MockClient) SyncGroupMap(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SyncGroupMap", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SyncGroupMap indicates an expected call of SyncGroupMap.
func (mr *MockClientMockRecorder) SyncGroupMap(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SyncGroupMap", reflect.TypeOf((*MockClient)(nil).SyncGroupMap), arg0)
}
