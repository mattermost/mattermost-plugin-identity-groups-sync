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
    const [totalCount, setTotalCount] = useState<number | null>(0);
    const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set());
    const [currentPage, setCurrentPage] = useState(0);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selectionError, setSelectionError] = useState<string | null>(null);
    const perPage = 20;

    const fetchCount = async (search: string) => {
        try {
            const response = await Client.getGroupsCount(search);
            if (response.count !== undefined) {
                setTotalCount(response.count);
            }
        } catch (err) {
            // If count is not supported (e.g., when using roles), set to null
            setTotalCount(null);
        }
    };

    // Create a debounced function for fetching count
    const debouncedFetchCount = useCallback(
        debounce(async (search: string) => {
            fetchCount(search);
        }, 500),
        []);

    // Fetch count whenever search term changes
    React.useEffect(() => {
        debouncedFetchCount(searchTerm);
    }, [searchTerm, debouncedFetchCount]);

    const debouncedSearch = useCallback(
        debounce(async (search: string) => {
            setCurrentPage(0);
            await fetchGroups(0, search, false);
        }, 500),
        [],
    );

    // Separate function to fetch groups based on page and search term
    const fetchGroups = async (page: number, search: string, showLoading = true) => {
        if (showLoading) {
            setIsLoading(true);
        }
        setError(null);

        try {
            const response = await Client.getGroups(page, perPage, search);
            if (response.groups) {
                const newGroupsMap: Map<string, Group> = new Map(
                    response.groups.map((group: Group) => [group.remote_id, group]),
                );
                setGroupsMap(newGroupsMap);
            }
            setCurrentPage(page);
        } catch (err) {
            setError('Failed to fetch groups. Please review your server logs and check your plugin configurations.');
        } finally {
            if (showLoading) {
                setIsLoading(false);
            }
        }
    };

    // Check if selection contains both linked and unlinked groups
    const hasMixedSelection = () => {
        const selectedGroupsArray = Array.from(selectedGroups);
        let hasLinked = false;
        let hasUnlinked = false;

        for (const remoteId of selectedGroupsArray) {
            const group = groupsMap.get(remoteId);
            if (group?.id && group.delete_at === 0) {
                hasLinked = true;
            } else {
                hasUnlinked = true;
            }

            if (hasLinked && hasUnlinked) {
                return true;
            }
        }

        return false;
    };

    // Handle page changes
    const handlePageChange = (newPage: number) => {
        setCurrentPage(newPage);
        fetchGroups(newPage, searchTerm, false);
    };

    // Fetch groups when component mounts
    React.useEffect(() => {
        fetchGroups(currentPage, searchTerm, true);
    }, []);

    const renderButtonText = () => {
        const selectedGroupsArray = Array.from(selectedGroups);
        const isUnlinking = selectedGroupsArray.some((remoteId) => {
            const group = groupsMap.get(remoteId);
            return group?.id && group.delete_at === 0;
        });

        return isUnlinking ? 'Unlink Selected Groups' : 'Link Selected Groups';
    };

    // Function to render table content based on loading and error states
    const renderTableContent = () => {
        if (isLoading) {
            return (
                <tr style={{width: '100%'}}>
                    <td
                        colSpan={2}
                        className='loading-container'
                    >
                        <div className='loading-spinner'>
                            <i className='fa fa-spinner fa-spin fa-2x'/>
                        </div>
                    </td>
                </tr>
            );
        }

        if (error) {
            return (
                <tr>
                    <td
                        colSpan={2}
                        className='error-container'
                    >
                        <div className='error-message'>
                            <i className='fa fa-exclamation-triangle'/>
                            <span>{error}</span>
                            <button
                                className='retry-button'
                                onClick={() => {
                                    fetchGroups(currentPage, searchTerm, true);
                                    fetchCount(searchTerm);
                                }}
                            >
                                {'Retry'}
                            </button>
                        </div>
                    </td>
                </tr>
            );
        }

        return Array.from(groupsMap.values()).map((group) => (
            <tr key={group.remote_id}>
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

                                // Check for mixed selection immediately
                                const updatedSelection = e.target.checked ?
                                    new Set([...selectedGroups, group.remote_id]) :
                                    new Set([...selectedGroups].filter((id) => id !== group.remote_id));

                                // Check if the new selection contains both linked and unlinked groups
                                let hasLinked = false;
                                let hasUnlinked = false;

                                for (const remoteId of updatedSelection) {
                                    const selectedGroup = groupsMap.get(remoteId);
                                    if (selectedGroup?.id && selectedGroup.delete_at === 0) {
                                        hasLinked = true;
                                    } else {
                                        hasUnlinked = true;
                                    }

                                    if (hasLinked && hasUnlinked) {
                                        setSelectionError('Cannot process mixed selections. Please select only linked or only unlinked groups.');
                                        return;
                                    }
                                }

                                // Clear error if selection is valid
                                setSelectionError(null);
                            }}
                        />
                        <span title={group.display_name}>{group.display_name}</span>
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
        ));
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
                            debouncedSearch(e.target.value);
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
                    disabled={selectedGroups.size === 0 || hasMixedSelection()}
                >
                    {renderButtonText()}
                </button>
            </div>

            {selectionError && (
                <div className='selection-error'>
                    <i className='fa fa-exclamation-triangle'/>
                    <span>{selectionError}</span>
                </div>
            )}

            <table className='groups-table'>
                <thead>
                    <tr>
                        <th>{'Name'}</th>
                        <th>{'Mattermost Linking'}</th>
                    </tr>
                </thead>
                <tbody>
                    {renderTableContent()}
                </tbody>
            </table>

            <div className='pagination'>
                {(() => {
                    if (totalCount === null) {
                        return (
                            <>
                                <span>{`Page ${currentPage + 1}`}</span>
                                <button
                                    disabled={currentPage === 0}
                                    onClick={() => handlePageChange(currentPage - 1)}
                                >
                                    <i className='fa fa-chevron-left'/>
                                </button>
                                <button
                                    disabled={groupsMap.size < perPage}
                                    onClick={() => handlePageChange(currentPage + 1)}
                                >
                                    <i className='fa fa-chevron-right'/>
                                </button>
                            </>
                        );
                    }
                    if (totalCount > 0) {
                        return (
                            <>
                                <span>{`${(currentPage * perPage) + 1} - ${Math.min((currentPage + 1) * perPage, totalCount)} of ${totalCount}`}</span>
                                <button
                                    disabled={currentPage === 0}
                                    onClick={() => handlePageChange(currentPage - 1)}
                                >
                                    <i className='fa fa-chevron-left'/>
                                </button>
                                <button
                                    disabled={(currentPage + 1) * perPage >= totalCount}
                                    onClick={() => handlePageChange(currentPage + 1)}
                                >
                                    <i className='fa fa-chevron-right'/>
                                </button>
                            </>
                        );
                    }
                    return <span>{'0 results'}</span>;
                })()}
            </div>
        </div>
    );
};

export default GroupsTable;
