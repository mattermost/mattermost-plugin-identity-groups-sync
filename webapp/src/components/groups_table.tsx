// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import debounce from 'lodash/debounce';
import React, {useState, useCallback} from 'react';
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
    const [currentPage, setCurrentPage] = useState(0);
    const perPage = 20;

    // Fetch total count only once on mount
    React.useEffect(() => {
        const fetchCount = async () => {
            const response = await Client.getGroupsCount();
            if (response.count) {
                setTotalCount(response.count);
            }
        };
        fetchCount();
    }, []);

    const debouncedSearch = useCallback(
        debounce(async (search: string) => {
            const response = await Client.getGroups(currentPage, perPage, search);
            if (response.groups) {
                const newGroupsMap: Map<string, Group> = new Map(
                    response.groups.map((group: Group) => [group.remote_id, group]),
                );
                setGroupsMap(newGroupsMap);
            }
        }, 500),
        [currentPage, perPage],
    );

    // Fetch groups when page changes or search term updates
    React.useEffect(() => {
        debouncedSearch(searchTerm);
        return () => debouncedSearch.cancel();
    }, [currentPage, searchTerm, debouncedSearch]);

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
                        onChange={(e) => {
                            setSearchTerm(e.target.value);
                            setCurrentPage(0); // Reset to first page on new search
                        }}
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
                                    newGroupsMap.set(linkedGroup.remote_id, linkedGroup);
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
                <span>{`${(currentPage * perPage) + 1} - ${Math.min((currentPage + 1) * perPage, totalCount)} of ${totalCount}`}</span>
                <button
                    disabled={currentPage === 0}
                    onClick={() => setCurrentPage(currentPage - 1)}
                >
                    <i className='fa fa-chevron-left'/>
                </button>
                <button
                    disabled={(currentPage + 1) * perPage >= totalCount}
                    onClick={() => setCurrentPage(currentPage + 1)}
                >
                    <i className='fa fa-chevron-right'/>
                </button>
            </div>
        </div>
    );
};

export default GroupsTable;
