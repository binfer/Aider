<?php
/**
 * Created by PhpStorm.
 * User: ge
 * Date: 1/6/2019
 * Time: 11:50 AM
 */
namespace common\traits;

use appapi\controller\CommonController;


/**
 *
 * # 辅助方法
 *
 * Trait Aider
 * @package common\traits
 *
 * binfer
 *
 */
trait Aider {

     static $aider = \Closure::class;

     public function self(CommonController $controller) {

         self::$aider = $controller;

     }


    /**
     *
     * #批量更新sql
     *
     * 结构体为：
     *
     * $data[0] = ["id"=>1, "SC"=>0.072, "KS"=>0.078, "KLB"=>0.068, "XYRB"=>0.068, "SSC"=>0.058, "FTC"=>0.048, "SYXW"=>0.038, "KLSF"=>0.028, "LHC"=>0.018];
     * $data[1] = ["id"=>2, "SC"=>0.073, "KS"=>0.078, "KLB"=>0.063, "XYRB"=>0.063, "SSC"=>0.051, "FTC"=>0.038, "SYXW"=>0.038, "KLSF"=>0.018, "LHC"=>0.018];
     * $data[2] = ["id"=>3, "SC"=>0.074, "KS"=>0.078, "KLB"=>0.062, "XYRB"=>0.064, "SSC"=>0.053, "FTC"=>0.058, "SYXW"=>0.058, "KLSF"=>0.078, "LHC"=>0.018];
     *
     * 基础返回格式: (截取部分结果)
     *
     *      UPDATE {{%agent}} SET `SC` = CASE `id`
            WHEN '1' THEN '0.072'
            WHEN '2' THEN '0.073'
            WHEN '3' THEN '0.074'
            END,`KS` = CASE `id`
            WHEN '1' THEN '0.078'
            WHEN '2' THEN '0.078'
            WHEN '3' THEN '0.078'
            END,`KLB` = CASE `id`
            WHEN '1' THEN '0.068'
            WHEN '2' THEN '0.063'
            WHEN '3' THEN '0.062'
            END WHERE id IN ('1','2','3')
     *
     * 调用: case_batchUpdate('agent', 'id', $data);
     *
     * @param $table        @表名
     * @param $key          @主键：以哪个字段作为条件判定
     * @param $data         @数据体，包含主键判定的数据 可以是数或者迭代数据
     *
     * @param \Closure|null $closure    @闭包接入条件，组成字符串返回
     *
     * @return bool|string
     *
     * binfer
     */
    public function case_batchUpdate($table, $key, array $data, \Closure $closure = null)
    {

        if ( empty($key) || empty($table) || empty($data)) {
            return false;
        }

        $updates = $this->case_parseUpdate($data, $key);

        $fields = array_column($data, $key);

        $fields = implode(',', array_map(function($value) {

            return "'{$value}'";
        }, $fields));

        return sprintf("UPDATE %s SET %s WHERE %s IN (%s) %s", $table, $updates, $key, $fields, $closure ? $closure() : '');

    }


    /**
     *
     * #组装update批量sql
     *
     * @param $data
     * @param $key
     * @return string
     *
     * binfer
     *
     */
    final private function case_parseUpdate(array $data, $key)
    {
        $sql = '';
        $keys = array_keys(current($data));

        foreach ($keys as $k=>$column) {
            if ($column === $key) {
                continue;
            }
            $sql .= sprintf("`%s` = CASE `%s` \n", $column, $key);

            foreach ($data as $line) {
                $sql .= sprintf("WHEN '%s' THEN '%s' \n", $line[$key], $line[$column]);
            }
            $sql .= "END,";
        }
        return rtrim($sql, ',');

    }

    /**
     * # 分块处理数据
     *
     * 逻辑部分通过闭包回调处理
     *
     * @param $datas
     * @param int $size
     * @param \Closure|null $closure
     *
     * binfer
     *
     */
    public function &chuck(array $datas, $size = 6, \Closure $closure=null) {


        $chunk = array_chunk($datas, $size, true);

        foreach ($chunk as $k => &$block) {

            $closure($k, $block);

        }
        return $chunk;

    }





    /**
     * #迭代处理一次性读取
     *
     * - 业务逻辑依赖通过闭包解决
     *
     * @param array $data
     * @param \Closure|null $closure
     * @return \Generator
     *
     * binfer
     */
    public function &yid(array $data, \Closure $closure=null) {

        foreach ($data as &$info) {
            if ($closure) {
                yield $closure($info);
            }
            yield $info;
        }
    }


    /**
     * #生成校验字符
     *
     * @param $mark
     * @return array
     *
     * binfer
     */
    static public function key_generate(string $mark) {

        $key    = sodium_crypto_auth_keygen();

        $sign   = sodium_crypto_auth($mark, $key);

        return [
            'key'  => base64_encode($key),
            'mark' => $mark,
            'sign' => base64_encode($sign)
        ];
    }



    /**
     * #验证校验字符
     *
     * @param string $sign
     * @param string $mark
     * @param string $key
     * @return bool
     *
     * binfer
     *
     */
    static public function key_check(string $sign, string $mark, string $key) {

        $sign = base64_decode($sign);
        $key  = base64_decode($key);

        return sodium_crypto_auth_verify($sign, $mark, $key);

    }


    /**
     *
     *
     * @param string $password  @密码， 单传生成hash
     * @param string $hash      @哈希， 传入password和hash检验密码
     * @param bool $rehash      @刷新， 传入password,hash,rehash验证密码，生成新的hash
     *
     * @return bool|string
     *
     * binfer
     */
    static public function password_handler(string $password, string $hash = '', bool $rehash = false) {


        if ( ! $hash) {
            $hash = password_hash($password, PASSWORD_DEFAULT);

            return $hash;
        }

        if (password_verify($password, $hash)) {

            if ($rehash && password_needs_rehash($hash, PASSWORD_DEFAULT, array('cost'=>11) )) {

                $newHash = password_hash($password, PASSWORD_DEFAULT);

                return $newHash;

            } else {

                return true;
            }
        }

        return false;


    }





}