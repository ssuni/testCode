<?php

namespace App\Repositories;

use App\Models\Community;
use App\Models\test;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\DB;

class ChannelRepository
{
    public function getChannel(int $channelId)
    {
        return test::select(
            'test.*',
            'podcast_categories.name as category_name',
            'test_channel_info.*',
        )
            ->leftJoin('podcast_categories', 'podcast_categories.id', '=', 'test.podcast_category_id')
            ->leftJoin('test_channel_info', 'test_channel_info.test_uid', '=', 'test.uid')
            ->where('test.uid', $channelId)
            ->first();
    }

    public function getChannels($ids): Collection
    {
        return test::whereIn('uid', $ids)
            ->where('display', 'Y')
            ->orderBy('created', 'desc')
            ->get();
    }

    public function getEpisodes(int $channelId): HasMany
    {
        return test::find($channelId)->episodes();
    }

    public function getCategoryChannel(mixed $category_id, mixed $sort, $limit, $offset)
    {
        return test::select('test.*',
            'test_channel_info.*',
        )
            ->leftJoin('test_channel_info', 'test_channel_info.test_uid', '=', 'test.uid')
            ->where('test.podcast_category_id', $category_id)
            ->where('test.display', 'Y')
            ->when(isset($sort), function ($query) use ($sort) {
                if (is_array($sort)) {
                    return $query->orderBy($sort[0], $sort[1]);
                }
            })
            ->when(!isset($sort), function ($query) {
                return $query->orderByDesc('test.pubdate')->orderByDesc('test.uid');
            })
//        ->orderByDesc('uid')
            ->when($offset, function ($query) use ($offset, $limit) {
                return $query->skip($offset * $limit);
            })
            ->when($limit, function ($query) use ($limit) {
                return $query->take($limit);
            });
    }

    public function getChannelPlayList($channelId)
    {
        return testPlayList::from('test_playlist as pp')
            ->select(DB::raw(
                'pp.id, pp.name, (select count(*) from test_items as ppi where ppi.test_playlist_id = pp.id) as count'
            ))
            ->where('test_uid', $channelId)
            ->where('display', 'Y')
            ->get();
    }

    public function getSearchChannels(array $conditions)
    {
        return test::when(isset($conditions['uid']), function ($query) use ($conditions) {
        })
            ->when(isset($conditions['display']), function ($query) use ($conditions) {
                return $query->where('display', $conditions['display']);
            })
            ->when(isset($conditions['sort']), function ($query) use ($conditions) {
                list($order, $direction) = explode('.', $conditions['sort']);
                $uid = implode(',', $conditions['uid']);
                if ($order == 'field' && is_array($conditions['uid'])) {
                    if (count($conditions['uid']) > 1) {
                        return $query->orderByRaw(DB::raw("FIELD (" . $uid . ") DESC"));
                    }
                } else {
                    return $query->orderBy($order, $direction)->orderBy('uid', 'desc');
                }
            })
            ->get();
    }
}
