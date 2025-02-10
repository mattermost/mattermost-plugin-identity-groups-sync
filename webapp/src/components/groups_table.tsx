// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React, {useState} from 'react';
import {Link} from 'react-router-dom';

import './groups_table.scss';

import Client from '../client';

interface Group {
    id: string;
    name: string;
    display_name: string;
    remote_id: string;
    source: string;
    allow_reference: boolean;
    delete_at: number;
}

const GroupsTable: React.FC = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [groupsMap, setGroupsMap] = useState<Map<string, Group>>(new Map());
    const [totalCount, setTotalCount] = useState(0);
    const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set());

    React.useEffect(() => {
        const fetchGroups = async () => {
            const response = await Client.getGroups(0, 20);
            if (response.groups) {
                const newGroupsMap: Map<string, Group> = new Map(
                    response.groups.map((group: Group) => [group.remote_id, group]),
                );
                setGroupsMap(newGroupsMap);
            }
        };

        const fetchCount = async () => {
            const response = await Client.getGroupsCount();
            if (response.count) {
                setTotalCount(response.count);
            }
        };

        fetchGroups();
        fetchCount();
    }, []);

    const renderButtonText = () => {
        const selectedGroupsArray = Array.from(selectedGroups);
        const isUnlinking = selectedGroupsArray.some((remoteId) => {
            const group = groupsMap.get(remoteId);
            return group?.id && group.delete_at === 0;
        });

        return isUnlinking ? 'Unlink Selected Groups' : 'Link Selected Groups';
    };

    return (
        <div className='groups-container'>
            <div className='header'>
                <h2>{'Keycloak Groups'}</h2>
                <p>
                    {'These groups are fetched from Keycloak.'}
                </p>
            </div>

            <div className='controls'>
                <div className='search-box'>
                    <input
                        type='text'
                        placeholder='Search'
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                    />
                </div>
                <button
                    className='primary-button'
                    onClick={async () => {
                        try {
                            const selectedGroupsArray = Array.from(selectedGroups);
                            const isUnlinking = selectedGroupsArray.some((remoteId) => {
                                const group = groupsMap.get(remoteId);
                                return group?.id && group.delete_at === 0;
                            });

                            if (isUnlinking) {
                                const results = await Promise.all(
                                    selectedGroupsArray.map((remoteId) =>
                                        Client.unlinkGroup(remoteId),
                                    ),
                                );

                                // Update the map with the unlinked groups
                                const newGroupsMap = new Map(groupsMap);
                                results.forEach((unlinkedGroup) => {
                                    if (unlinkedGroup) {
                                        const existingGroup = newGroupsMap.get(unlinkedGroup.remote_id);
                                        if (existingGroup) {
                                            newGroupsMap.set(unlinkedGroup.remote_id, {
                                                ...existingGroup,
                                                ...unlinkedGroup,
                                            });
                                        }
                                    }
                                });
                                setGroupsMap(newGroupsMap);
                            } else {
                                const results = await Promise.all(
                                    selectedGroupsArray.map((remoteId) =>
                                        Client.linkGroup(remoteId),
                                    ),
                                );

                                // Update the map with the linked groups
                                const newGroupsMap = new Map(groupsMap);
                                results.forEach((linkedGroup) => {
                                    if (linkedGroup) {
                                        const existingGroup = newGroupsMap.get(linkedGroup.remote_id);
                                        if (existingGroup) {
                                            newGroupsMap.set(linkedGroup.remote_id, {
                                                ...existingGroup,
                                                ...linkedGroup,
                                            });
                                        }
                                    }
                                });
                                setGroupsMap(newGroupsMap);
                            }
                            setSelectedGroups(new Set());
                        } catch (error) {
                            // TODO: Add proper error handling/user notification
                        }
                    }}
                    disabled={selectedGroups.size === 0}
                >
                    {renderButtonText()}
                </button>
            </div>

            <table className='groups-table'>
                <thead>
                    <tr>
                        <th>{'Name'}</th>
                        <th>{'Mattermost Linking'}</th>
                    </tr>
                </thead>
                <tbody>
                    {Array.from(groupsMap.values()).map((group) => (
                        <tr key={group.id}>
                            <td>
                                <label className='checkbox-label'>
                                    <input
                                        type='checkbox'
                                        checked={selectedGroups.has(group.remote_id)}
                                        onChange={(e) => {
                                            const newSelected = new Set(selectedGroups);
                                            if (e.target.checked) {
                                                newSelected.add(group.remote_id);
                                            } else {
                                                newSelected.delete(group.remote_id);
                                            }
                                            setSelectedGroups(newSelected);
                                        }}
                                    />
                                    <span>{group.display_name}</span>
                                </label>
                            </td>
                            <td>
                                <div className='linking-status'>
                                    {group.id && group.delete_at === 0 ? (
                                        <>
                                            <i className='icon-link'/> {'Linked'}
                                            <Link
                                                to={`/admin_console/user_management/groups/${group.id}`}
                                                className='action-link'
                                            >{'Edit'}</Link>
                                        </>
                                    ) : (
                                        <>
                                            <i className='icon-unlink'/> {'Not Linked'}
                                        </>
                                    )}
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>

            <div className='pagination'>
                <span>{`1 - ${Math.min(20, totalCount)} of ${totalCount}`}</span>
                <button disabled={true}>{'&lt;'}</button>
                <button disabled={true}>{'&gt;'}</button>
            </div>
        </div>
    );
};

export default GroupsTable;
