// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/mattermost/mattermost-plugin-groups/server/groups (interfaces: GoCloak)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gocloak "github.com/Nerzal/gocloak/v13"
	gomock "github.com/golang/mock/gomock"
)

// MockGoCloak is a mock of GoCloak interface.
type MockGoCloak struct {
	ctrl     *gomock.Controller
	recorder *MockGoCloakMockRecorder
}

// MockGoCloakMockRecorder is the mock recorder for MockGoCloak.
type MockGoCloakMockRecorder struct {
	mock *MockGoCloak
}

// NewMockGoCloak creates a new mock instance.
func NewMockGoCloak(ctrl *gomock.Controller) *MockGoCloak {
	mock := &MockGoCloak{ctrl: ctrl}
	mock.recorder = &MockGoCloakMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockGoCloak) EXPECT() *MockGoCloakMockRecorder {
	return m.recorder
}

// GetGroup mocks base method.
func (m *MockGoCloak) GetGroup(arg0 context.Context, arg1, arg2, arg3 string) (*gocloak.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroup", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*gocloak.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroup indicates an expected call of GetGroup.
func (mr *MockGoCloakMockRecorder) GetGroup(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroup", reflect.TypeOf((*MockGoCloak)(nil).GetGroup), arg0, arg1, arg2, arg3)
}

// GetGroupMembers mocks base method.
func (m *MockGoCloak) GetGroupMembers(arg0 context.Context, arg1, arg2, arg3 string, arg4 gocloak.GetGroupsParams) ([]*gocloak.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupMembers", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].([]*gocloak.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupMembers indicates an expected call of GetGroupMembers.
func (mr *MockGoCloakMockRecorder) GetGroupMembers(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupMembers", reflect.TypeOf((*MockGoCloak)(nil).GetGroupMembers), arg0, arg1, arg2, arg3, arg4)
}

// GetGroups mocks base method.
func (m *MockGoCloak) GetGroups(arg0 context.Context, arg1, arg2 string, arg3 gocloak.GetGroupsParams) ([]*gocloak.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroups", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]*gocloak.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroups indicates an expected call of GetGroups.
func (mr *MockGoCloakMockRecorder) GetGroups(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroups", reflect.TypeOf((*MockGoCloak)(nil).GetGroups), arg0, arg1, arg2, arg3)
}

// GetGroupsCount mocks base method.
func (m *MockGoCloak) GetGroupsCount(arg0 context.Context, arg1, arg2 string, arg3 gocloak.GetGroupsParams) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupsCount", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupsCount indicates an expected call of GetGroupsCount.
func (mr *MockGoCloakMockRecorder) GetGroupsCount(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupsCount", reflect.TypeOf((*MockGoCloak)(nil).GetGroupsCount), arg0, arg1, arg2, arg3)
}

// LoginClient mocks base method.
func (m *MockGoCloak) LoginClient(arg0 context.Context, arg1, arg2, arg3 string, arg4 ...string) (*gocloak.JWT, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1, arg2, arg3}
	for _, a := range arg4 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "LoginClient", varargs...)
	ret0, _ := ret[0].(*gocloak.JWT)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LoginClient indicates an expected call of LoginClient.
func (mr *MockGoCloakMockRecorder) LoginClient(arg0, arg1, arg2, arg3 interface{}, arg4 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1, arg2, arg3}, arg4...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoginClient", reflect.TypeOf((*MockGoCloak)(nil).LoginClient), varargs...)
}

// RefreshToken mocks base method.
func (m *MockGoCloak) RefreshToken(arg0 context.Context, arg1, arg2, arg3, arg4 string) (*gocloak.JWT, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RefreshToken", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*gocloak.JWT)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RefreshToken indicates an expected call of RefreshToken.
func (mr *MockGoCloakMockRecorder) RefreshToken(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RefreshToken", reflect.TypeOf((*MockGoCloak)(nil).RefreshToken), arg0, arg1, arg2, arg3, arg4)
}
